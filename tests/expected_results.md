# Expected Security Analysis Results

This file documents the expected security findings for test contracts to ensure CI validation works correctly.

## access_control_issues.sol
**Expected Issues: 4+**
- `unprotected-initializer`: initialize() function lacks access control
- `missing-access-modifiers`: setOwner() lacks access control
- `missing-access-modifiers`: withdraw() lacks access control
- `default-visibility`: updateBalance() has implicit internal visibility

## reentrancy_issues.sol
**Expected Issues: 2+**
- `classic-reentrancy`: withdraw() updates state after external call
- `readonly-reentrancy`: withdrawBasedOnBalance() vulnerable to view reentrancy

## validation_issues.sol
**Expected Issues: 5+**
- `missing-zero-address-check`: setToken() missing zero address validation
- `array-bounds-check`: updateValue() lacks bounds checking
- `division-before-multiplication`: calculateReward() precision loss
- `parameter-consistency`: transfer() inconsistent parameter validation
- `unchecked-external-call`: callExternalContract() doesn't check call result

## clean_contract.sol
**Expected Issues: 0**
- Should find no security issues (uses OpenZeppelin, proper patterns)
- May have import warnings (acceptable for clean contract)

## CI Validation Rules
- Vulnerable contracts must trigger security findings
- Clean contract should have minimal/no security issues
- Total findings across all test files should be 11+ issues
- High/Critical severity findings should be present