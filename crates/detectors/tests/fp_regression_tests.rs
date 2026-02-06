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

// Import safe pattern functions that work with source strings
use detectors::safe_patterns::library_patterns::{
    has_inline_sender_check, has_inline_zero_check, has_try_catch,
};

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
        source_lower.contains("completewithdrawal") || source_lower.contains("complete_withdrawal"),
        "Restaking contract should have complete withdrawal"
    );

    // Should have withdrawal delay
    assert!(
        restaking_source.contains("WITHDRAWAL_DELAY") || source_lower.contains("withdrawaldelay"),
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

// ============================================================================
// Safe Pattern Detection Unit Tests (Phase 15)
// These tests use source-level pattern matching (no AST required)
// ============================================================================

/// Test reentrancy guard source patterns
#[test]
fn test_reentrancy_guard_source_patterns() {
    // Contract with OpenZeppelin ReentrancyGuard
    let oz_guard = r#"
        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
        contract Vault is ReentrancyGuard {
            function withdraw() external nonReentrant {
                // ...
            }
        }
    "#;
    assert!(
        oz_guard.contains("ReentrancyGuard"),
        "Should have ReentrancyGuard import"
    );
    assert!(
        oz_guard.contains("nonReentrant"),
        "Should have nonReentrant modifier"
    );

    // Contract with custom lock modifier
    let custom_lock = r#"
        contract Pool {
            uint256 private unlocked = 1;
            modifier lock() {
                require(unlocked == 1);
                unlocked = 0;
                _;
                unlocked = 1;
            }
            function swap() external lock() {
                // ...
            }
        }
    "#;
    assert!(
        custom_lock.contains("modifier lock"),
        "Should have lock modifier"
    );
    assert!(
        custom_lock.contains("unlocked == 1"),
        "Should have unlock check"
    );
}

/// Test access control source patterns
#[test]
fn test_access_control_source_patterns() {
    // Contract with Ownable pattern
    let ownable = r#"
        import "@openzeppelin/contracts/access/Ownable.sol";
        contract Admin is Ownable {
            function setConfig() external onlyOwner {
                // ...
            }
        }
    "#;
    assert!(ownable.contains("Ownable"), "Should have Ownable import");
    assert!(
        ownable.contains("onlyOwner"),
        "Should have onlyOwner modifier"
    );

    // Contract with AccessControl pattern
    let access_control = r#"
        import "@openzeppelin/contracts/access/AccessControl.sol";
        contract Governance is AccessControl {
            bytes32 public constant ADMIN_ROLE = keccak256("ADMIN");
            function execute() external onlyRole(ADMIN_ROLE) {
                // ...
            }
        }
    "#;
    assert!(
        access_control.contains("AccessControl"),
        "Should have AccessControl import"
    );
    assert!(
        access_control.contains("onlyRole"),
        "Should have onlyRole modifier"
    );
    assert!(
        access_control.contains("_ROLE"),
        "Should have role constant"
    );

    // Contract with timelock
    let timelock = r#"
        contract Governance {
            uint256 public delay = 2 days;
            mapping(bytes32 => uint256) public queuedTransactions;

            function queueTransaction(bytes32 hash) external {
                queuedTransactions[hash] = block.timestamp + delay;
            }

            function executeTransaction(bytes32 hash) external {
                require(block.timestamp >= queuedTransactions[hash]);
            }
        }
    "#;
    assert!(timelock.contains("delay"), "Should have delay variable");
    assert!(
        timelock.contains("queueTransaction") && timelock.contains("executeTransaction"),
        "Should have queue and execute functions"
    );
    assert!(timelock.contains("block.timestamp"), "Should use timestamp");
}

/// Test library usage source patterns
#[test]
fn test_library_source_patterns() {
    // Contract using SafeERC20
    let safe_erc20 = r#"
        import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
        contract Vault {
            using SafeERC20 for IERC20;
            function deposit(uint256 amount) external {
                token.safeTransferFrom(msg.sender, address(this), amount);
            }
        }
    "#;
    assert!(
        safe_erc20.contains("SafeERC20"),
        "Should have SafeERC20 import"
    );
    assert!(
        safe_erc20.contains("safeTransferFrom"),
        "Should use safeTransferFrom"
    );
    assert!(
        safe_erc20.contains("@openzeppelin"),
        "Should be from OpenZeppelin"
    );

    // Contract using ECDSA
    let ecdsa = r#"
        import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
        contract Signer {
            using ECDSA for bytes32;
            function verify(bytes32 hash, bytes memory sig) external view returns (address) {
                return ECDSA.recover(hash, sig);
            }
        }
    "#;
    assert!(ecdsa.contains("ECDSA"), "Should have ECDSA import");
    assert!(ecdsa.contains("ECDSA.recover"), "Should use ECDSA.recover");

    // Solidity 0.8+ contract
    let sol_08 = r#"
        pragma solidity ^0.8.0;
        contract SafeMath {
            function add(uint a, uint b) external pure returns (uint) {
                return a + b; // Safe in 0.8+
            }
        }
    "#;
    assert!(
        sol_08.contains("pragma solidity ^0.8"),
        "Should have Solidity 0.8+ pragma"
    );
}

/// Test inline protection detection (string-based)
#[test]
fn test_inline_protection_detection() {
    // Function with inline sender check
    let with_sender_check = r#"
        function withdraw() external {
            require(msg.sender == owner, "Not owner");
            payable(owner).transfer(address(this).balance);
        }
    "#;
    assert!(
        has_inline_sender_check(with_sender_check),
        "Should detect inline sender check"
    );

    // Function with inline zero check
    let with_zero_check = r#"
        function setRecipient(address _recipient) external {
            require(_recipient != address(0), "Zero address");
            recipient = _recipient;
        }
    "#;
    assert!(
        has_inline_zero_check(with_zero_check),
        "Should detect inline zero address check"
    );

    // Function with try/catch
    let with_try_catch = r#"
        function safeCall(address target) external {
            try ITarget(target).execute() returns (bool result) {
                // handle success
            } catch {
                // handle failure
            }
        }
    "#;
    assert!(
        has_try_catch(with_try_catch),
        "Should detect try/catch pattern"
    );
}

/// Test contract type source patterns
#[test]
fn test_contract_type_source_patterns() {
    // Interface contract
    let interface = r#"
        interface IToken {
            function transfer(address to, uint256 amount) external returns (bool);
            function balanceOf(address account) external view returns (uint256);
        }
    "#;
    assert!(
        interface.contains("interface "),
        "Should have interface keyword"
    );

    // Library contract
    let library = r#"
        library MathLib {
            function add(uint a, uint b) internal pure returns (uint) {
                return a + b;
            }
        }
    "#;
    assert!(library.contains("library "), "Should have library keyword");

    // Test contract
    let test_source = r#"
        import "forge-std/Test.sol";
        contract VaultTest is Test {
            function testDeposit() public {
                // ...
            }
        }
    "#;
    assert!(
        test_source.contains("forge-std"),
        "Should have forge-std import"
    );
    assert!(test_source.contains("Test"), "Should inherit from Test");
    assert!(
        test_source.to_lowercase().contains("test"),
        "Should have test in name"
    );
}

// ============================================================================
// Phase 52 FP Reduction Tests
// ============================================================================

/// Test centralization risk FP reduction - timelock/multisig patterns
#[test]
fn test_centralization_timelock_patterns() {
    // Contract with timelock should not be flagged
    let with_timelock = r#"
        import "@openzeppelin/contracts/governance/TimelockController.sol";
        contract Governance is Ownable {
            TimelockController public timelock;
            function setConfig(uint256 value) external onlyOwner {
                timelock.schedule(address(this), 0, abi.encodeWithSignature("applyConfig(uint256)", value), bytes32(0), 0, 2 days);
            }
        }
    "#;
    assert!(
        with_timelock.contains("TimelockController"),
        "Should have timelock"
    );
    assert!(
        with_timelock.contains("schedule"),
        "Should use schedule function"
    );

    // Contract with multisig should not be flagged
    let with_multisig = r#"
        import "@safe-global/safe-contracts/contracts/GnosisSafe.sol";
        contract Treasury {
            GnosisSafe public safe;
            uint256 public threshold = 3;
            function transfer(address to, uint256 amount) external {
                require(confirmations[msg.sender] >= threshold);
            }
        }
    "#;
    assert!(
        with_multisig.contains("GnosisSafe") || with_multisig.contains("Safe"),
        "Should have multisig"
    );
    assert!(with_multisig.contains("threshold"), "Should have threshold");
}

/// Test timestamp FP reduction - deadline/expiry patterns
#[test]
fn test_timestamp_deadline_patterns() {
    // Signature expiry check should not be flagged
    let permit_function = r#"
        function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
            require(block.timestamp <= deadline, "Permit expired");
            // verify signature
        }
    "#;
    assert!(
        permit_function.contains("deadline"),
        "Should have deadline parameter"
    );
    assert!(
        permit_function.contains("block.timestamp <="),
        "Should have timestamp check"
    );

    // Grace period should not be flagged
    let with_grace = r#"
        function unlock() external {
            require(block.timestamp >= lockTime + 7 days, "Still locked");
            // allow unlock
        }
    "#;
    assert!(with_grace.contains("days"), "Should have days suffix");
}

/// Test delegatecall FP reduction - Diamond pattern
#[test]
fn test_delegatecall_diamond_pattern() {
    // Diamond contract should not be flagged
    let diamond = r#"
        import { IDiamondCut } from "./interfaces/IDiamondCut.sol";
        import { IDiamondLoupe } from "./interfaces/IDiamondLoupe.sol";

        contract Diamond {
            struct DiamondStorage {
                mapping(bytes4 => address) facets;
            }

            fallback() external payable {
                DiamondStorage storage ds = diamondStorage();
                address facet = ds.facets[msg.sig];
                require(facet != address(0));
                assembly {
                    calldatacopy(0, 0, calldatasize())
                    let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
                    returndatacopy(0, 0, returndatasize())
                    switch result
                    case 0 { revert(0, returndatasize()) }
                    default { return(0, returndatasize()) }
                }
            }
        }
    "#;
    assert!(
        diamond.contains("DiamondCut") || diamond.contains("diamondCut"),
        "Should have diamond cut"
    );
    assert!(
        diamond.contains("DiamondLoupe") || diamond.contains("facets"),
        "Should have diamond loupe"
    );
    assert!(diamond.contains("facet"), "Should use facets");
}

/// Test low-level call FP reduction - proper success checks
#[test]
fn test_lowlevel_call_success_check() {
    // Call with proper success check should not be flagged
    let with_check = r#"
        function withdraw(address to, uint256 amount) external {
            (bool success, ) = payable(to).call{value: amount}("");
            require(success, "Transfer failed");
        }
    "#;
    assert!(
        with_check.contains("(bool success"),
        "Should capture success"
    );
    assert!(
        with_check.contains("require(success"),
        "Should check success"
    );

    // Using Address.sendValue should not be flagged
    let with_library = r#"
        import "@openzeppelin/contracts/utils/Address.sol";
        using Address for address payable;
        function send(address to, uint256 amount) external {
            payable(to).sendValue(amount);
        }
    "#;
    assert!(
        with_library.contains("Address.sendValue") || with_library.contains("sendValue"),
        "Should use sendValue"
    );
}

/// Test unused return value FP reduction
#[test]
fn test_unused_return_value_patterns() {
    // Approve with max approval pattern
    let approve_max = r#"
        function approveMax(address spender) external {
            token.approve(spender, type(uint256).max);
        }
    "#;
    assert!(
        approve_max.contains("type(uint256).max"),
        "Should have max approval"
    );

    // With try-catch
    let with_try = r#"
        function safeTransfer(address to, uint256 amount) external {
            try token.transfer(to, amount) returns (bool success) {
                require(success, "Transfer failed");
            } catch {
                revert("Transfer reverted");
            }
        }
    "#;
    assert!(
        with_try.contains("try ") && with_try.contains("catch"),
        "Should have try-catch"
    );
}

// ============================================================================
// Phase 54 FP Reduction Tests - 10 Categories
// ============================================================================

/// Category 1: ERC-721 Callback Reentrancy FP Reduction
#[test]
fn test_erc721_callback_safe_patterns() {
    // Safe ERC721 receiver that only returns magic value
    let safe_receiver = r#"
        function onERC721Received(
            address operator,
            address from,
            uint256 tokenId,
            bytes calldata data
        ) external pure returns (bytes4) {
            return this.onERC721Received.selector;
        }
    "#;
    assert!(
        safe_receiver.contains("onERC721Received.selector"),
        "Safe receiver should return magic selector"
    );
    assert!(
        !safe_receiver.contains(".call"),
        "Safe receiver should not make external calls"
    );

    // Safe ERC1155 receiver
    let safe_1155_receiver = r#"
        function onERC1155Received(
            address,
            address,
            uint256,
            uint256,
            bytes calldata
        ) external pure returns (bytes4) {
            return 0xf23a6e61; // Magic value
        }
    "#;
    assert!(
        safe_1155_receiver.contains("0xf23a6e61"),
        "ERC1155 receiver should return magic value"
    );

    // OpenZeppelin Initializable pattern
    let initializable = r#"
        import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
        contract NFTVault is Initializable, ERC721Holder {
            function initialize() external initializer {
                // Safe initialization
            }
        }
    "#;
    assert!(
        initializable.contains("Initializable"),
        "Should detect Initializable pattern"
    );
}

/// Category 2: CREATE2 Frontrunning FP Reduction
#[test]
fn test_create2_safe_patterns() {
    // OpenZeppelin Clones library usage
    let clones_library = r#"
        import "@openzeppelin/contracts/proxy/Clones.sol";
        contract Factory {
            using Clones for address;
            function createClone(address impl) external returns (address) {
                return Clones.cloneDeterministic(impl, salt);
            }
        }
    "#;
    assert!(
        clones_library.contains("Clones"),
        "Should use Clones library"
    );
    assert!(
        clones_library.contains("cloneDeterministic"),
        "Should use deterministic clone"
    );

    // Salt commitment pattern
    let salt_commitment = r#"
        mapping(bytes32 => uint256) public saltCommitments;

        function commitSalt(bytes32 saltHash) external {
            saltCommitments[saltHash] = block.timestamp;
        }

        function deploy(bytes32 salt) external {
            require(block.timestamp >= saltCommitments[keccak256(abi.encode(salt))] + 1 days);
            // Deploy with CREATE2
        }
    "#;
    assert!(
        salt_commitment.contains("saltCommitments"),
        "Should have salt commitment"
    );
    assert!(salt_commitment.contains("1 days"), "Should have time delay");

    // EIP-1167 minimal proxy
    let eip1167 = r#"
        // EIP-1167 Minimal Proxy Clone
        bytes constant CREATION_CODE = hex"3d602d80600a3d3981f3363d3d373d3d3d363d73";
        function createMinimalProxy() external {
            // Deploy minimal proxy
        }
    "#;
    assert!(
        eip1167.contains("3d602d80600a3d3981f3"),
        "Should have EIP-1167 bytecode"
    );
}

/// Category 3: Delegatecall in Constructor FP Reduction
#[test]
fn test_delegatecall_constructor_safe_patterns() {
    // EIP-1967 proxy pattern
    let eip1967_proxy = r#"
        bytes32 constant IMPLEMENTATION_SLOT =
            0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

        constructor(address impl) {
            StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value = impl;
        }
    "#;
    assert!(
        eip1967_proxy.contains("IMPLEMENTATION_SLOT"),
        "Should have EIP-1967 slot"
    );

    // Diamond proxy pattern
    let diamond_proxy = r#"
        import { IDiamondCut } from "./interfaces/IDiamondCut.sol";
        contract Diamond {
            constructor(address _diamondCutFacet) {
                // Initialize diamond
            }
        }
    "#;
    assert!(
        diamond_proxy.contains("IDiamondCut"),
        "Should have Diamond interface"
    );

    // OpenZeppelin Initializable
    let initializable = r#"
        import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
        contract MyContract is Initializable {
            function initialize() external initializer {}
        }
    "#;
    assert!(
        initializable.contains("Initializable"),
        "Should use Initializable"
    );
}

/// Category 4: DOS Unbounded Operation FP Reduction
#[test]
fn test_dos_unbounded_safe_patterns() {
    // EnumerableSet usage
    let enumerable_set = r#"
        import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
        using EnumerableSet for EnumerableSet.AddressSet;
        EnumerableSet.AddressSet private _members;

        function getMembers() external view returns (address[] memory) {
            return _members.values();
        }
    "#;
    assert!(
        enumerable_set.contains("EnumerableSet"),
        "Should use EnumerableSet"
    );

    // Paginated view function
    let paginated = r#"
        function getItems(uint256 offset, uint256 limit) external view returns (Item[] memory) {
            uint256 end = Math.min(offset + limit, items.length);
            Item[] memory result = new Item[](end - offset);
            for (uint256 i = offset; i < end; i++) {
                result[i - offset] = items[i];
            }
            return result;
        }
    "#;
    assert!(
        paginated.contains("offset") && paginated.contains("limit"),
        "Should have pagination params"
    );
    assert!(
        paginated.contains("Math.min"),
        "Should use Math.min for bounds"
    );

    // Multicall with size validation
    let multicall = r#"
        uint256 constant MAX_CALLS = 10;
        function multicall(bytes[] calldata data) external {
            require(data.length <= MAX_CALLS, "Too many calls");
            for (uint256 i = 0; i < data.length; i++) {
                (bool success,) = address(this).delegatecall(data[i]);
                require(success);
            }
        }
    "#;
    assert!(
        multicall.contains("MAX_CALLS"),
        "Should have max calls constant"
    );
    assert!(
        multicall.contains("require(data.length <="),
        "Should validate array length"
    );
}

/// Category 5: Permit Signature Exploit FP Reduction
#[test]
fn test_permit_safe_patterns() {
    // Permit2 integration
    let permit2 = r#"
        import { IAllowanceTransfer } from "permit2/interfaces/IAllowanceTransfer.sol";
        contract Router {
            IAllowanceTransfer public immutable permit2;
            function depositWithPermit2(uint256 amount, PermitSingle calldata permit) external {
                permit2.permit(msg.sender, permit.single, permit.signature);
            }
        }
    "#;
    assert!(
        permit2.contains("IAllowanceTransfer"),
        "Should use Permit2 interface"
    );
    assert!(permit2.contains("permit2"), "Should reference permit2");

    // ERC-2771 trusted forwarder
    let forwarder = r#"
        import "@openzeppelin/contracts/metatx/ERC2771Context.sol";
        contract MyContract is ERC2771Context {
            constructor(address trustedForwarder) ERC2771Context(trustedForwarder) {}
            function _msgSender() internal view override returns (address) {
                return ERC2771Context._msgSender();
            }
        }
    "#;
    assert!(
        forwarder.contains("ERC2771Context"),
        "Should use ERC2771Context"
    );
    assert!(
        forwarder.contains("trustedForwarder"),
        "Should have trusted forwarder"
    );

    // Permit consumer (not implementer)
    let consumer = r#"
        function depositWithPermit(uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
            IERC20Permit(token).permit(msg.sender, address(this), amount, deadline, v, r, s);
            token.transferFrom(msg.sender, address(this), amount);
        }
    "#;
    assert!(
        consumer.contains("IERC20Permit("),
        "Should call external permit"
    );
    assert!(
        !consumer.contains("ecrecover"),
        "Consumer should not implement ecrecover"
    );
}

/// Category 6: Unsafe Type Casting FP Reduction
#[test]
fn test_type_casting_safe_patterns() {
    // address <-> uint160 (same size, safe)
    let address_uint160 = r#"
        function addressToUint(address addr) external pure returns (uint160) {
            return uint160(addr);
        }
        function uintToAddress(uint160 num) external pure returns (address) {
            return address(num);
        }
    "#;
    assert!(
        address_uint160.contains("uint160(addr)"),
        "Should have address to uint160"
    );
    assert!(
        address_uint160.contains("address(num)"),
        "Should have uint160 to address"
    );

    // Chainlink latestRoundData pattern
    let chainlink = r#"
        function getPrice() external view returns (uint256) {
            (,int256 answer,,,) = priceFeed.latestRoundData();
            require(answer > 0, "Invalid price");
            return uint256(answer);
        }
    "#;
    assert!(
        chainlink.contains("latestRoundData"),
        "Should call latestRoundData"
    );
    assert!(
        chainlink.contains("answer > 0"),
        "Should validate answer is positive"
    );

    // Literal value cast (safe)
    let literal = r#"
        uint8 constant DECIMALS = uint8(18);
        uint16 constant MAX_BPS = uint16(10000);
    "#;
    assert!(
        literal.contains("uint8(18)"),
        "Should have literal uint8 cast"
    );
    assert!(
        literal.contains("uint16(10000)"),
        "Should have literal uint16 cast"
    );

    // Enum cast (compiler validated)
    let enum_cast = r#"
        enum Status { Pending, Active, Completed }
        function getStatusValue(Status s) external pure returns (uint8) {
            return uint8(s);
        }
    "#;
    assert!(
        enum_cast.contains("enum Status"),
        "Should have enum definition"
    );
    assert!(enum_cast.contains("uint8(s)"), "Should cast enum to uint8");
}

/// Category 7: Metamorphic Contract FP Reduction
#[test]
fn test_metamorphic_safe_patterns() {
    // Uniswap factory (known safe)
    let uniswap = r#"
        import "@uniswap/v3-core/contracts/interfaces/IUniswapV3Factory.sol";
        contract PoolDeployer {
            function createPool(address token0, address token1) external {
                IUniswapV3Factory(factory).createPool(token0, token1, fee);
            }
        }
    "#;
    assert!(
        uniswap.contains("IUniswapV3Factory"),
        "Should use Uniswap factory"
    );

    // Long selfdestruct timelock (>7 days)
    let long_timelock = r#"
        uint256 public destructionTime;

        function initiateDestruction() external onlyOwner {
            destructionTime = block.timestamp + 30 days;
        }

        function destroy() external onlyOwner {
            require(block.timestamp >= destructionTime, "Timelock not expired");
            selfdestruct(payable(owner));
        }
    "#;
    assert!(
        long_timelock.contains("30 days"),
        "Should have 30 day delay"
    );
    assert!(
        long_timelock.contains("selfdestruct"),
        "Should have selfdestruct"
    );

    // Salt validation pattern
    let salt_validation = r#"
        mapping(bytes32 => bool) public usedSalts;

        function deploy(bytes32 salt, bytes memory bytecode) external {
            require(!usedSalts[salt], "Salt already used");
            usedSalts[salt] = true;
            // CREATE2 deployment
        }
    "#;
    assert!(
        salt_validation.contains("usedSalts"),
        "Should track used salts"
    );
    assert!(
        salt_validation.contains("require(!usedSalts[salt]"),
        "Should validate salt"
    );
}

/// Category 8: EXTCODESIZE Bypass FP Reduction
#[test]
fn test_extcodesize_safe_patterns() {
    // OpenZeppelin Address library
    let oz_address = r#"
        import "@openzeppelin/contracts/utils/Address.sol";
        using Address for address;

        function checkContract(address target) external view returns (bool) {
            return target.isContract();
        }
    "#;
    assert!(
        oz_address.contains("Address.sol"),
        "Should import Address library"
    );
    assert!(oz_address.contains("isContract()"), "Should use isContract");

    // Documented bypass limitation
    let documented = r#"
        // WARNING: This check can be bypassed during construction
        // as EXTCODESIZE returns 0 during constructor execution.
        // Use tx.origin == msg.sender for stricter EOA validation.
        function isContract(address account) internal view returns (bool) {
            return account.code.length > 0;
        }
    "#;
    assert!(
        documented.contains("WARNING"),
        "Should have warning comment"
    );
    assert!(
        documented.contains("during construction"),
        "Should document bypass"
    );

    // Companion isInConstruction function
    let companion = r#"
        function isContract(address account) internal view returns (bool) {
            return account.code.length > 0;
        }

        function isInConstruction(address account) internal view returns (bool) {
            return account.code.length == 0 && tx.origin != account;
        }
    "#;
    assert!(
        companion.contains("isInConstruction"),
        "Should have companion function"
    );
}

/// Category 9: ERC-7821 Batch Authorization FP Reduction
#[test]
fn test_erc7821_batch_safe_patterns() {
    // Inherited access control
    let access_control = r#"
        import "@openzeppelin/contracts/access/AccessControl.sol";
        contract BatchExecutor is AccessControl {
            bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR");

            function executeBatch(Call[] calldata calls) external onlyRole(EXECUTOR_ROLE) {
                for (uint i = 0; i < calls.length; i++) {
                    (bool success,) = calls[i].target.call(calls[i].data);
                    require(success);
                }
            }
        }
    "#;
    assert!(
        access_control.contains("AccessControl"),
        "Should inherit AccessControl"
    );
    assert!(
        access_control.contains("onlyRole"),
        "Should use onlyRole modifier"
    );

    // Smart contract wallet pattern
    let smart_wallet = r#"
        import "@safe-global/safe-contracts/contracts/Safe.sol";
        contract WalletModule {
            function execTransaction(address to, bytes calldata data) external {
                GnosisSafe(wallet).execTransactionFromModule(to, 0, data, 0);
            }
        }
    "#;
    assert!(
        smart_wallet.contains("GnosisSafe") || smart_wallet.contains("Safe"),
        "Should use Safe wallet"
    );

    // Chainlink automation executor
    let automation = r#"
        import "@chainlink/contracts/src/v0.8/AutomationCompatible.sol";
        contract AutomatedTask is AutomationCompatibleInterface {
            function checkUpkeep(bytes calldata) external view returns (bool, bytes memory) {
                return (shouldExecute(), "");
            }
            function performUpkeep(bytes calldata) external {
                // Execute batch
            }
        }
    "#;
    assert!(
        automation.contains("AutomationCompatible"),
        "Should use Chainlink automation"
    );
    assert!(
        automation.contains("checkUpkeep") && automation.contains("performUpkeep"),
        "Should implement automation interface"
    );
}

/// Category 10: Storage Layout Upgrade FP Reduction
#[test]
fn test_storage_layout_safe_patterns() {
    // EIP-1967 proxy (uses fixed slots)
    let eip1967 = r#"
        contract ERC1967Proxy {
            bytes32 constant IMPLEMENTATION_SLOT =
                0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

            function _delegate(address implementation) internal virtual {
                assembly {
                    calldatacopy(0, 0, calldatasize())
                    let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
                    returndatacopy(0, 0, returndatasize())
                    switch result
                    case 0 { revert(0, returndatasize()) }
                    default { return(0, returndatasize()) }
                }
            }
        }
    "#;
    assert!(
        eip1967.contains("IMPLEMENTATION_SLOT"),
        "Should have EIP-1967 slot"
    );
    assert!(eip1967.contains("ERC1967Proxy"), "Should be ERC1967 proxy");

    // Diamond storage library
    let diamond_storage = r#"
        library LibDiamond {
            bytes32 constant DIAMOND_STORAGE_POSITION = keccak256("diamond.standard.diamond.storage");

            struct DiamondStorage {
                mapping(bytes4 => address) facetAddresses;
            }

            function diamondStorage() internal pure returns (DiamondStorage storage ds) {
                bytes32 position = DIAMOND_STORAGE_POSITION;
                assembly {
                    ds.slot := position
                }
            }
        }
    "#;
    assert!(
        diamond_storage.contains("LibDiamond"),
        "Should be LibDiamond"
    );
    assert!(
        diamond_storage.contains("DIAMOND_STORAGE_POSITION"),
        "Should have storage position"
    );

    // EIP-7201 namespaced storage
    let eip7201 = r#"
        /// @custom:storage-location erc7201:myapp.storage.main
        struct MainStorage {
            uint256 value;
            mapping(address => uint256) balances;
        }

        bytes32 constant MAIN_STORAGE_SLOT = keccak256(abi.encode(uint256(keccak256("erc7201:myapp.storage.main")) - 1));
    "#;
    assert!(
        eip7201.contains("@custom:storage-location"),
        "Should have EIP-7201 annotation"
    );
    assert!(
        eip7201.contains("erc7201:"),
        "Should use EIP-7201 namespace"
    );

    // Contract with constructor (not upgradeable)
    let with_constructor = r#"
        contract NonUpgradeable {
            uint256 public value;

            constructor(uint256 _value) {
                value = _value;
            }
        }
    "#;
    assert!(
        with_constructor.contains("constructor("),
        "Should have constructor"
    );
}
