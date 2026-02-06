# Ground Truth Baseline Documentation

This directory contains baseline measurements for the SolidityDefend false positive reduction process. These baselines track findings across 18 test targets and are used to measure the effectiveness of each FP reduction round.

## Test Targets (18)

### Clean Contracts (5) — All findings are false positives
1. `tests/contracts/clean_examples/clean_contract.sol`
2. `tests/contracts/fp_benchmarks/safe_amm_pool.sol`
3. `tests/contracts/fp_benchmarks/safe_chainlink_consumer.sol`
4. `tests/contracts/fp_benchmarks/safe_erc4626_vault.sol`
5. `tests/contracts/fp_benchmarks/safe_flash_loan_provider.sol`

### Vulnerable Contracts (13) — Mix of TPs and FPs
6. `tests/contracts/basic_vulnerabilities/reentrancy_issues.sol`
7. `tests/contracts/basic_vulnerabilities/validation_issues.sol`
8. `tests/contracts/vulnerable/`
9. `tests/contracts/flash_loans/`
10. `tests/contracts/erc4626_vaults/`
11. `tests/contracts/price-manipulation/`
12. `tests/contracts/cross_chain/`
13. `tests/contracts/delegatecall/`
14. `tests/contracts/signatures/`
15. `tests/contracts/specialized/`
16. `tests/contracts/restaking/`
17. `tests/contracts/account_abstraction/`
18. `tests/contracts/amm_context/`

## Known True Positives (Must Always Be Detected)

| TP Category | Contract | Expected Detector |
|-------------|----------|-------------------|
| Reentrancy | `reentrancy_issues.sol` | `classic-reentrancy` |
| Access Control | `validation_issues.sol` | `array-bounds-check`, `logic-error-patterns` |
| Vault Inflation | `erc4626_vaults/` | `vault-share-inflation` |
| Chain-ID Missing | `cross_chain/` | `missing-chainid-validation`, `cross-chain-replay` |

## How to Run a Baseline Scan

```bash
# Build release binary
cargo build --release

# Run scan on all 18 targets
for f in \
  tests/contracts/clean_examples/clean_contract.sol \
  tests/contracts/fp_benchmarks/safe_amm_pool.sol \
  tests/contracts/fp_benchmarks/safe_chainlink_consumer.sol \
  tests/contracts/fp_benchmarks/safe_erc4626_vault.sol \
  tests/contracts/fp_benchmarks/safe_flash_loan_provider.sol \
  tests/contracts/basic_vulnerabilities/reentrancy_issues.sol \
  tests/contracts/basic_vulnerabilities/validation_issues.sol \
  tests/contracts/vulnerable/ \
  tests/contracts/flash_loans/ \
  tests/contracts/erc4626_vaults/ \
  tests/contracts/price-manipulation/ \
  tests/contracts/cross_chain/ \
  tests/contracts/delegatecall/ \
  tests/contracts/signatures/ \
  tests/contracts/specialized/ \
  tests/contracts/restaking/ \
  tests/contracts/account_abstraction/ \
  tests/contracts/amm_context/; do
  COUNT=$(./target/release/soliditydefend -f json "$f" 2>/dev/null | \
    python3 -c "
import sys, json
data = sys.stdin.read()
lines = data.split('\n')
json_lines, in_json, brace_count = [], False, 0
for line in lines:
    if not in_json and line.strip().startswith('{'):
        in_json = True
    if in_json:
        json_lines.append(line)
        brace_count += line.count('{') - line.count('}')
        if brace_count == 0: break
print(len(json.loads('\n'.join(json_lines)).get('findings', [])))" 2>/dev/null)
  echo "$COUNT $f"
done
```

## Baselines

See individual baseline files:
- [v1.10.19-baseline.md](v1.10.19-baseline.md) — Current baseline (after FP reduction v5)

## FP Reduction History

| Version | Round | Detectors | FPs Eliminated | Total Findings | Clean FPs |
|---------|-------|-----------|----------------|----------------|-----------|
| v1.10.14 | v1 | 10 | — | — | — |
| v1.10.16 | v2 | 10 | 37 | — | — |
| v1.10.17 | v3 | 10 | 88 | — | — |
| v1.10.18 | v4 | 10 | 52 (net -22) | 1,776 | 45 |
| v1.10.19 | v5 | 20 | 191 | 1,585 | 42 |
