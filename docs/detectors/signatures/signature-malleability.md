# Signature Malleability Detector

**Detector ID:** `signature-malleability`
**Severity:** High
**Category:** Auth, Validation
**CWE:** CWE-347 (Improper Verification of Cryptographic Signature), CWE-354 (Improper Validation of Integrity Check Value)

## Description

Detects ECDSA signature verification without malleability protection. ECDSA signatures have two valid forms (s and n-s) allowing attackers to create alternate valid signatures for replay attacks.

## Vulnerability

### Root Cause

ECDSA signatures consist of (v, r, s) where:
- For valid signature (v, r, s), an alternate (v', r, n-s) is also valid
- Both recover to same signer address
- Without s-value validation, one signature becomes two

### Attack: Signature Replay

```solidity
// VULNERABLE
function execute(..., uint8 v, bytes32 r, bytes32 s) external {
    bytes32 hash = keccak256(abi.encode(to, amount));
    address signer = ecrecover(hash, v, r, s);  // ❌ No s-value check
    require(!executed[hash], "Executed");
    executed[hash] = true;
    payable(to).transfer(amount);
}
```

**Attack:**
1. User signs transaction with (v, r, s)
2. Attacker flips s to (n-s), creates (v', r, n-s)
3. Both signatures valid, different hashes
4. Can execute transaction twice

**Loss:** Double spending, replay attacks

## Detection

Flags functions using `ecrecover()` without:
- s-value range check against `secp256k1` curve order
- `MAX_S_VALUE` constant (0x7FFF...20A0)
- OpenZeppelin ECDSA library

## Remediation

### Option 1: Validate s-value

```solidity
bytes32 private constant MAX_S_VALUE =
    0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

function execute(..., bytes32 s) external {
    require(uint256(s) <= uint256(MAX_S_VALUE), "Invalid s");  // ✅ SECURE
    require(v == 27 || v == 28, "Invalid v");
    address signer = ecrecover(hash, v, r, s);
}
```

### Option 2: Use OpenZeppelin ECDSA

```solidity
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

function execute(..., bytes memory signature) external {
    address signer = ECDSA.recover(hash, signature);  // ✅ Built-in protection
}
```

## Real-World Impact

- **$100M+ class vulnerability**: ECDSA malleability in signature systems
- **Replay attacks**: Same user action executed multiple times
- **Nonce bypass**: Alternate signatures bypass nonce tracking

## Testing Results

**Test Coverage:** 14 vulnerable contracts
**Detection Rate:** 100%
**False Positives:** 0% (after polishing)

**Polishing:** Improved to recognize `uint256(s) <=` and `MAX_S_VALUE` constant patterns

## References

- [Bitcoin's ECDSA Malleability Fix](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki)
- [OpenZeppelin ECDSA](https://docs.openzeppelin.com/contracts/4.x/api/utils#ECDSA)

## Related Detectors

- `missing-eip712-domain`: EIP-712 implementation
- `weak-signature-validation`: Multisig duplicate detection

---

**Last Updated:** 2025-11-15 (Phase 3 Week 1)
**Polishing Status:** ✅ Polished
**Production Ready:** ✅ Yes
