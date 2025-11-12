# Delegatecall Return Value Ignored

**Detector ID:** `delegatecall-return-ignored`
**Category:** External Calls / Best Practices
**Severity:** ⚠️ **HIGH**
**CWE:** [CWE-252: Unchecked Return Value](https://cwe.mitre.org/data/definitions/252.html)
**Confidence:** High

---

## Description

This detector identifies delegatecall operations where the return value (success/failure status) is not properly checked or validated. When delegatecall fails silently, contracts may assume operations succeeded when they actually failed, leading to state corruption, fund loss, and incorrect contract behavior.

Delegatecall is a low-level operation that:
1. Returns a boolean indicating success (`true`) or failure (`false`)
2. Can fail for various reasons (revert, out of gas, invalid target)
3. Does NOT automatically revert on failure (unlike regular calls in newer Solidity)
4. Requires explicit checking of the return value

When return values are ignored:
- Failed operations go unnoticed
- Contract continues execution with corrupt state
- Funds may be lost without detection
- Critical operations silently fail

---

## Vulnerability Pattern

### ❌ Statement-Position Delegatecall

```solidity
contract IgnoredReturnDelegatecall {
    address public implementation;

    function execute(bytes calldata data) external {
        // CRITICAL: Return value completely ignored!
        implementation.delegatecall(data);
        // If delegatecall fails, we'll never know
        // Contract continues as if everything succeeded
    }
}
```

**Why it's vulnerable:**
- No `(bool success, ...)` capture
- Failure goes completely unnoticed
- Subsequent code executes regardless of success
- No way to detect or handle errors

### ❌ Captured But Not Validated

```solidity
contract CapturedButNotChecked {
    address public implementation;

    function execute(bytes calldata data) external returns (bool) {
        (bool success, ) = implementation.delegatecall(data);
        // VULNERABLE: success captured but never validated
        // Just returned to caller who might also ignore it
        return success;
    }
}
```

**Why it's vulnerable:**
- Return value captured but not checked
- No `require(success)` or `if (!success)` validation
- Caller may also ignore the return value
- Error silently propagates

### ❌ Only Data Returned, Not Success

```solidity
contract DataOnlyCapture {
    address public implementation;

    function executeForData(bytes calldata data) external returns (bytes memory) {
        (, bytes memory result) = implementation.delegatecall(data);
        // VULNERABLE: success not captured, only data
        // If delegatecall failed, result is empty but we don't know why
        return result;
    }
}
```

**Why it's vulnerable:**
- Success status discarded
- Empty return data could mean success with no data OR failure
- No way to distinguish between valid empty result and error

### ❌ Assembly Delegatecall Without Checking

```solidity
contract AssemblyDelegatecallIgnored {
    address public implementation;

    function execute(bytes calldata data) external {
        address impl = implementation;

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            // VULNERABLE: result not checked, always returns
            return(0, returndatasize())
        }
    }
}
```

**Why it's vulnerable:**
- Assembly delegatecall result stored but ignored
- Always returns, even when `result == 0` (failure)
- Failure data returned as if it were success data

---

## ✅ Secure Implementations

### Option 1: Require with Revert

```solidity
contract CheckedDelegatecall {
    address public implementation;

    event ExecutionSuccess(bytes data);

    function execute(bytes calldata data) external {
        (bool success, bytes memory returnData) = implementation.delegatecall(data);

        // SECURE: Check return value
        require(success, "Delegatecall failed");

        emit ExecutionSuccess(data);
    }
}
```

**Why it's secure:**
- Captures both `success` and `returnData`
- Reverts entire transaction if delegatecall fails
- Clear error message
- No state changes if operation fails

### Option 2: Bubble Up Revert Reason

```solidity
contract BubbleRevertReason {
    address public implementation;

    function executeWithRevert(bytes calldata data) external {
        (bool success, bytes memory returnData) = implementation.delegatecall(data);

        // SECURE: Bubble up the actual revert reason
        if (!success) {
            assembly {
                revert(add(returnData, 32), mload(returnData))
            }
        }
    }
}
```

**Why it's secure:**
- Preserves original revert reason
- Provides maximum debugging information
- Fails fast with clear error context

### Option 3: Try-Catch with Error Handling

```solidity
contract TryCatchWithHandling {
    address public implementation;

    event ExecutionFailed(bytes reason);

    function executeWithTryCatch(bytes calldata data) external {
        try this.internalDelegatecall(data) {
            // Success path
        } catch Error(string memory reason) {
            // SECURE: Handle error with reason
            emit ExecutionFailed(bytes(reason));
            revert(reason);
        } catch (bytes memory lowLevelData) {
            // SECURE: Handle low-level errors
            emit ExecutionFailed(lowLevelData);
            revert("Low-level call failed");
        }
    }

    function internalDelegatecall(bytes calldata data) external {
        (bool success, bytes memory returnData) = implementation.delegatecall(data);
        require(success, string(returnData));
    }
}
```

**Why it's secure:**
- Comprehensive error handling
- Logs failure events for debugging
- Still reverts to prevent state corruption
- Distinguishes between error types

### Option 4: Assembly with Proper Checking

```solidity
contract AssemblyDelegatecallChecked {
    address public implementation;

    function execute(bytes calldata data) external {
        address impl = implementation;

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())

            // SECURE: Check result and revert on failure
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
```

**Why it's secure:**
- Explicit success check with `switch`
- `case 0` handles failure (reverts)
- `default` handles success (returns)
- No execution continues after failure

### Option 5: State Updates Only After Success

```solidity
contract StateChangeAfterCheck {
    address public implementation;
    uint256 public counter;

    event Executed(uint256 newCounter);

    function execute(bytes calldata data) external {
        (bool success, ) = implementation.delegatecall(data);

        // SECURE: Only update state if delegatecall succeeded
        require(success, "Delegatecall failed");

        counter++;
        emit Executed(counter);
    }
}
```

**Why it's secure:**
- State changes only occur after verification
- Atomic operation (all or nothing)
- No partial state updates on failure

---

## Real-World Impact

### Known Vulnerabilities

1. **Proxy Initialization Failures**: Multiple proxy implementations have suffered from:
   - Failed initialization delegatecalls going undetected
   - Proxies deployed in broken/uninitialized state
   - Funds sent to contracts that appeared functional but weren't

2. **Batch Operation Silent Failures**: DeFi protocols have experienced:
   - Batch delegatecall operations where some calls failed silently
   - Partial execution leading to state corruption
   - Fund accounting discrepancies

3. **Upgrade Failures**: Upgradeable contracts have had:
   - Failed upgrade initializations that weren't detected
   - Contracts stuck in intermediate states
   - Data migrations that partially completed

### Example Scenario

```solidity
// Vulnerable upgrade function
function upgrade(address newImpl, bytes memory initData) external {
    require(msg.sender == owner, "Only owner");

    implementation = newImpl;

    // VULNERABLE: If initialization fails, proxy is broken!
    if (initData.length > 0) {
        newImpl.delegatecall(initData);
        // No check! Proxy now points to uninitialized implementation
    }
}

// Secure version
function upgradeSecure(address newImpl, bytes memory initData) external {
    require(msg.sender == owner, "Only owner");

    address oldImpl = implementation;
    implementation = newImpl;

    if (initData.length > 0) {
        (bool success, ) = newImpl.delegatecall(initData);

        // SECURE: Rollback if initialization fails
        if (!success) {
            implementation = oldImpl;
            revert("Initialization failed, upgrade rolled back");
        }
    }

    emit Upgraded(newImpl);
}
```

---

## Detection Strategy

The detector identifies unchecked delegatecalls by:

1. **Statement-Position Detection**:
   - Looks for delegatecall not assigned to any variable
   - Pattern: `target.delegatecall(data);` with no capture

2. **Unvalidated Capture Detection**:
   - Finds `(bool success, ...) = delegatecall(...)`
   - Checks for subsequent `require(success)`, `if (!success)`, or `assert(success)`
   - Flags if return value not validated

3. **Data-Only Capture Detection**:
   - Identifies `(, bytes memory data) = delegatecall(...)`
   - Success status deliberately ignored

4. **Assembly Delegatecall Analysis**:
   - Scans assembly blocks for delegatecall
   - Checks for `switch result` or `if iszero(result)`
   - Flags if no failure handling

5. **Context Analysis**:
   - Checks all function types (regular, fallback, constructor, modifier)
   - Special attention to proxy upgrade and initialization functions

---

## Mitigation Recommendations

### For All Delegatecalls

1. **Always Capture Return Value**:
   ```solidity
   (bool success, bytes memory data) = target.delegatecall(callData);
   ```

2. **Always Validate Success**:
   ```solidity
   require(success, "Delegatecall failed");
   // or
   if (!success) {
       revert("Delegatecall failed");
   }
   ```

3. **Consider Bubbling Up Errors**:
   ```solidity
   if (!success) {
       assembly {
           revert(add(data, 32), mload(data))
       }
   }
   ```

### For Critical Operations

1. **Use Try-Catch**:
   ```solidity
   try this.internalDelegatecall(data) {
       // success
   } catch {
       // handle error
       revert("Operation failed");
   }
   ```

2. **Implement Rollback Logic**:
   ```solidity
   // Store old state
   address oldImpl = implementation;

   // Try change
   implementation = newImpl;
   (bool success, ) = newImpl.delegatecall(initData);

   // Rollback if failed
   if (!success) {
       implementation = oldImpl;
       revert("Rollback");
   }
   ```

3. **Emit Events**:
   ```solidity
   if (success) {
       emit OperationSucceeded(data);
   } else {
       emit OperationFailed(data, returnData);
       revert("Operation failed");
   }
   ```

### For Batch Operations

```solidity
function batchExecute(bytes[] calldata data) external returns (bool[] memory results) {
    results = new bool[](data.length);
    uint256 successCount = 0;

    for (uint256 i = 0; i < data.length; i++) {
        (bool success, ) = library.delegatecall(data[i]);
        results[i] = success;

        if (success) {
            successCount++;
        } else {
            emit CallFailed(i, data[i]);
        }
    }

    // Option: Require all succeed
    require(successCount == data.length, "Not all calls succeeded");

    // Option: Allow partial success but return results
    return results;
}
```

---

## Configuration

### Enable/Disable

```yaml
# .soliditydefend.yml
detectors:
  delegatecall-return-ignored:
    enabled: true
    severity: high
```

### Severity Levels

- **High**: Default setting
  - Silent failures can cause significant issues
  - State corruption likely
  - Fund loss possible

Could be **Critical** if:
- Used in fund transfer logic
- Part of upgrade mechanism
- Controls access to critical functions

---

## Best Practices

### Do's ✅

1. **Always Check Returns**: Validate `success` before continuing
2. **Use Require**: Simple and clear: `require(success, "...")`
3. **Bubble Up Errors**: Preserve revert reasons when possible
4. **Test Failure Cases**: Explicitly test what happens when delegatecall fails
5. **Document Assumptions**: Make it clear what happens on failure

### Don'ts ❌

1. **Don't Ignore Returns**: Never use delegatecall as a statement
2. **Don't Just Return Success**: Validate it, don't just pass it along
3. **Don't Skip Assembly Checks**: Always check `result` in assembly
4. **Don't Update State Before Check**: Verify success first
5. **Don't Assume Success**: Delegatecall can fail for many reasons

---

## Related Detectors

- `dangerous-delegatecall`: Detects unsafe delegatecall patterns
- `delegatecall-user-controlled`: Detects user-controlled delegatecall targets
- `fallback-delegatecall-unprotected`: Detects unprotected fallback delegatecalls
- `unchecked-return-value`: General detector for unchecked return values

---

## References

- [Solidity Documentation: Low-Level Calls](https://docs.soliditylang.org/en/latest/units-and-global-variables.html#members-of-address-types)
- [CWE-252: Unchecked Return Value](https://cwe.mitre.org/data/definitions/252.html)
- [OpenZeppelin: Proxy Upgrade Best Practices](https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies)
- [Consensys Best Practices: Handle errors in external calls](https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/)

---

**Last Updated:** 2025-11-11
**Detector Version:** 1.3.3+
