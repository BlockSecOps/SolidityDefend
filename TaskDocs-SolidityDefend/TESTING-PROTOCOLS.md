# Testing Protocols

Standardized testing procedures for validating SolidityDefend functionality.

## Test Categories

1. **Unit Tests** - Core functionality
2. **Integration Tests** - End-to-end analysis
3. **Real-World Tests** - Production contracts
4. **Framework Tests** - Project detection

## Real-World Contract Sources

### Proxy Contracts

**Source:** OpenZeppelin v5.0.0

```bash
mkdir -p /tmp/realworld-tests/proxy && cd /tmp/realworld-tests/proxy

curl -sL "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v5.0.0/contracts/proxy/Proxy.sol" -o Proxy.sol
curl -sL "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v5.0.0/contracts/proxy/ERC1967/ERC1967Proxy.sol" -o ERC1967Proxy.sol
curl -sL "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v5.0.0/contracts/proxy/ERC1967/ERC1967Utils.sol" -o ERC1967Utils.sol
curl -sL "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v5.0.0/contracts/proxy/transparent/TransparentUpgradeableProxy.sol" -o TransparentUpgradeableProxy.sol
curl -sL "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v5.0.0/contracts/proxy/beacon/BeaconProxy.sol" -o BeaconProxy.sol
curl -sL "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v5.0.0/contracts/proxy/beacon/UpgradeableBeacon.sol" -o UpgradeableBeacon.sol
```

**Expected Results:**
- Files: 6
- Findings: 28 (4 Critical, 17 High, 7 Medium)
- Time: <0.1s

### Upgradeable Contracts

**Source:** OpenZeppelin Upgradeable + Compound

```bash
mkdir -p /tmp/realworld-tests/upgradeable && cd /tmp/realworld-tests/upgradeable

curl -sL "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts-upgradeable/v5.0.0/contracts/proxy/utils/Initializable.sol" -o Initializable.sol
curl -sL "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts-upgradeable/v5.0.0/contracts/proxy/utils/UUPSUpgradeable.sol" -o UUPSUpgradeable.sol
curl -sL "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts-upgradeable/v5.0.0/contracts/access/OwnableUpgradeable.sol" -o OwnableUpgradeable.sol
curl -sL "https://raw.githubusercontent.com/compound-finance/compound-protocol/master/contracts/Comptroller.sol" -o Comptroller.sol
curl -sL "https://raw.githubusercontent.com/compound-finance/compound-protocol/master/contracts/ComptrollerStorage.sol" -o ComptrollerStorage.sol
```

**Expected Results:**
- Files: 5
- Findings: 139 (21 Critical, 31 High, 67 Medium)
- Time: ~1s

### Foundry Project (Permit2)

**Source:** Uniswap Permit2

```bash
mkdir -p /tmp/realworld-tests/foundry-permit2/src && cd /tmp/realworld-tests/foundry-permit2

echo '[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc = "0.8.17"' > foundry.toml

curl -sL "https://raw.githubusercontent.com/Uniswap/permit2/main/src/Permit2.sol" -o src/Permit2.sol
curl -sL "https://raw.githubusercontent.com/Uniswap/permit2/main/src/SignatureTransfer.sol" -o src/SignatureTransfer.sol
curl -sL "https://raw.githubusercontent.com/Uniswap/permit2/main/src/AllowanceTransfer.sol" -o src/AllowanceTransfer.sol
curl -sL "https://raw.githubusercontent.com/Uniswap/permit2/main/src/EIP712.sol" -o src/EIP712.sol
```

**Expected Results:**
- Framework: Foundry (auto-detected)
- Files: 4
- Findings: 54 (2 Critical, 30 High, 16 Medium)
- Time: <0.1s

### Hardhat Project (Aave V3)

**Source:** Aave V3 Core

```bash
mkdir -p /tmp/realworld-tests/hardhat-aave/contracts && cd /tmp/realworld-tests/hardhat-aave

echo 'module.exports = { solidity: { version: "0.8.10" } };' > hardhat.config.js

curl -sL "https://raw.githubusercontent.com/aave/aave-v3-core/master/contracts/protocol/pool/Pool.sol" -o contracts/Pool.sol
curl -sL "https://raw.githubusercontent.com/aave/aave-v3-core/master/contracts/protocol/pool/PoolStorage.sol" -o contracts/PoolStorage.sol
curl -sL "https://raw.githubusercontent.com/aave/aave-v3-core/master/contracts/protocol/libraries/logic/SupplyLogic.sol" -o contracts/SupplyLogic.sol
curl -sL "https://raw.githubusercontent.com/aave/aave-v3-core/master/contracts/protocol/libraries/logic/BorrowLogic.sol" -o contracts/BorrowLogic.sol
curl -sL "https://raw.githubusercontent.com/aave/aave-v3-core/master/contracts/flashloan/base/FlashLoanSimpleReceiverBase.sol" -o contracts/FlashLoanSimpleReceiverBase.sol
```

**Expected Results:**
- Framework: Hardhat (auto-detected)
- Files: 5
- Findings: 146 (23 Critical, 44 High, 51 Medium)
- Time: ~0.3s

## Running All Tests

### Quick Test Script

```bash
#!/bin/bash
# test-all.sh

echo "=== SolidityDefend Test Suite ==="

# Unit tests
echo -e "\n[1/5] Running unit tests..."
cargo test --workspace --lib

# Version check
echo -e "\n[2/5] Checking version..."
./target/release/soliditydefend --version

# Detector count
echo -e "\n[3/5] Counting detectors..."
COUNT=$(./target/release/soliditydefend --list-detectors 2>&1 | wc -l)
echo "Detectors: $COUNT"

# Proxy test
echo -e "\n[4/5] Testing proxy contracts..."
./target/release/soliditydefend /tmp/realworld-tests/proxy/ 2>&1 | tail -20

# Framework tests
echo -e "\n[5/5] Testing framework detection..."
./target/release/soliditydefend /tmp/realworld-tests/foundry-permit2/ 2>&1 | head -15
./target/release/soliditydefend /tmp/realworld-tests/hardhat-aave/ 2>&1 | head -15

echo -e "\n=== Tests Complete ==="
```

## Validation Criteria

### Pass Criteria

| Test | Requirement |
|------|-------------|
| Unit Tests | 0 failures |
| Detector Count | = 333 |
| Version Output | Matches Cargo.toml |
| Proxy Test | 20-35 findings |
| Foundry Detection | "Framework: Foundry" |
| Hardhat Detection | "Framework: Hardhat" |

### Failure Investigation

If tests fail:

1. Check Rust build errors: `cargo build --release 2>&1`
2. Verify detector compilation: `cargo test -p detectors`
3. Check file access: `ls -la /tmp/realworld-tests/`
4. Review error output: `soliditydefend file.sol 2>&1`

## Continuous Testing

### Pre-Commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

cargo test --workspace --lib --quiet || exit 1
./target/release/soliditydefend --list-detectors >/dev/null || exit 1
```

### CI/CD Integration

```yaml
# .github/workflows/test.yml
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: cargo build --release
      - name: Unit Tests
        run: cargo test --workspace --lib
      - name: Detector Count
        run: |
          COUNT=$(./target/release/soliditydefend --list-detectors | wc -l)
          [ "$COUNT" -eq 333 ] || exit 1
```
