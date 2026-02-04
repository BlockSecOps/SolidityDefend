# False Positive Benchmark Contracts

This directory contains Solidity contracts that implement **proper security patterns**. These contracts are used to verify that SolidityDefend's detectors correctly identify safe implementations and avoid false positives.

## Purpose

- **Regression Testing**: Ensure safe patterns are recognized across detector updates
- **FP Validation**: Verify contracts with proper protections don't trigger findings
- **Pattern Documentation**: Serve as reference implementations for secure patterns

## Benchmark Contracts

| Contract | Category | Safe Patterns Implemented |
|----------|----------|---------------------------|
| `safe_erc4626_vault.sol` | Vault/DeFi | decimalsOffset (virtual shares), MINIMUM_DEPOSIT, INITIAL_SHARE_LOCK (dead shares), tracked assets, ReentrancyGuard |
| `safe_chainlink_consumer.sol` | Oracle | AggregatorV3Interface, multi-oracle (primary + secondary), MAX_STALENESS, MAX_DEVIATION, answeredInRound validation |
| `safe_flash_loan_provider.sol` | Flash Loan | ERC-3156 compliance, CALLBACK_SUCCESS validation, balance before/after, fee bounds, ReentrancyGuard, msg.sender validation |
| `safe_amm_pool.sol` | AMM/DeFi | TWAP oracle (cumulative prices), MINIMUM_LIQUIDITY (dead shares), slippage protection, deadline (MEV), k invariant validation |

## Running Tests

```bash
# Run FP regression tests
cargo test -p detectors --test fp_regression_tests

# Analyze benchmarks (should produce minimal/no findings)
soliditydefend tests/contracts/fp_benchmarks/

# Verify specific pattern detection
cargo test -p detectors --test fp_regression_tests test_safe_chainlink
```

## Adding New Benchmarks

1. **Create Contract**: Add a new `.sol` file implementing the safe pattern
2. **Include Safety Measures**: Implement all relevant protections for the category
3. **Add Test**: Create corresponding test in `crates/detectors/tests/fp_regression_tests.rs`
4. **Document**: Update this README with the new contract

### Contract Requirements

- SPDX license identifier
- Pragma statement (Solidity ^0.8.20+)
- Comprehensive NatSpec documentation
- All safety patterns for the category implemented
- Valid Solidity syntax (should compile)

## Safe Patterns Reference

### Oracle Patterns
- Chainlink `AggregatorV3Interface` with `latestRoundData()`
- Staleness check: `block.timestamp - updatedAt <= MAX_STALENESS`
- Answer validation: `require(answer > 0)`
- Round validation: `require(answeredInRound >= roundId)`
- Multi-oracle with deviation check

### Flash Loan Patterns
- ERC-3156 `CALLBACK_SUCCESS` constant
- `onFlashLoan` callback with `msg.sender` validation
- Balance before/after repayment validation
- `nonReentrant` modifier

### Vault Patterns
- `_decimalsOffset()` for virtual shares (OpenZeppelin pattern)
- Dead shares: mint to `address(0)` on first deposit
- Minimum deposit requirement
- Internal asset tracking (not `balanceOf`)

### AMM Patterns
- Cumulative price tracking for TWAP
- `MINIMUM_LIQUIDITY` burned to dead address
- Slippage protection (`minAmountOut`)
- Transaction deadline
- K invariant validation

## Related Documentation

- [FP Reduction Guide](../../../TaskDocs-SolidityDefend/FP-REDUCTION.md)
- [Safe Patterns Library](../../../crates/detectors/src/safe_patterns/)
- [Detector Documentation](../../../docs/detectors/README.md)
