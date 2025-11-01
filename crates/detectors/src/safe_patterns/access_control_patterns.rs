use crate::types::AnalysisContext;

/// Detect OpenZeppelin Ownable pattern
///
/// Standard ownership pattern from OpenZeppelin contracts.
///
/// Patterns detected:
/// - `Ownable` import or inheritance
/// - `owner()` function
/// - `onlyOwner` modifier
/// - `transferOwnership` function
/// - `renounceOwnership` function
pub fn has_ownable_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Ownable import
    if source.contains("import") && source.contains("Ownable") {
        return true;
    }

    // Pattern 2: Ownable inheritance
    if source.contains("is Ownable") || source.contains("is OwnableUpgradeable") {
        return true;
    }

    // Pattern 3: Standard owner() function
    if source.contains("function owner()") && source.contains("returns") {
        return true;
    }

    // Pattern 4: onlyOwner modifier usage
    if source.contains("modifier onlyOwner()") || source.contains("onlyOwner modifier") {
        return true;
    }

    // Pattern 5: Two-step ownership transfer (Ownable2Step)
    if source.contains("pendingOwner") && source.contains("acceptOwnership") {
        return true;
    }

    false
}

/// Detect OpenZeppelin AccessControl pattern
///
/// Role-based access control from OpenZeppelin.
///
/// Patterns detected:
/// - `AccessControl` import or inheritance
/// - `hasRole` function usage
/// - Role constants (DEFAULT_ADMIN_ROLE, etc.)
/// - `grantRole` and `revokeRole` functions
/// - `onlyRole` modifier
pub fn has_access_control_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: AccessControl import
    if source.contains("import") && source.contains("AccessControl") {
        return true;
    }

    // Pattern 2: AccessControl inheritance
    if source.contains("is AccessControl") {
        return true;
    }

    // Pattern 3: hasRole usage
    if source.contains("hasRole(") {
        return true;
    }

    // Pattern 4: Role constants
    if source.contains("DEFAULT_ADMIN_ROLE") || source.contains("_ROLE = keccak256") {
        return true;
    }

    // Pattern 5: Role management functions
    if source.contains("grantRole(") && source.contains("revokeRole(") {
        return true;
    }

    // Pattern 6: onlyRole modifier
    if source.contains("onlyRole(") {
        return true;
    }

    false
}

/// Detect timelock pattern
///
/// Time-delayed execution patterns for governance operations.
///
/// Patterns detected:
/// - Compound Timelock pattern
/// - OpenZeppelin TimelockController
/// - Custom timelock with delay enforcement
/// - Queue + execute pattern
pub fn has_timelock_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: TimelockController import/inheritance
    if source.contains("TimelockController") {
        return true;
    }

    // Pattern 2: Compound Timelock
    if source.contains("import") && source.contains("Timelock") {
        return true;
    }

    // Pattern 3: Queue and execute functions
    if source.contains("queueTransaction") && source.contains("executeTransaction") {
        return true;
    }

    // Pattern 4: Delay enforcement
    if source.contains("delay") && source.contains("timestamp") {
        if source.contains("require(") || source.contains("if (") {
            return true;
        }
    }

    // Pattern 5: scheduleBatch or schedule functions (OpenZeppelin pattern)
    if source.contains("schedule(") || source.contains("scheduleBatch(") {
        return true;
    }

    // Pattern 6: timelock variable with block.timestamp check
    if source.contains("timelock") && source.contains("block.timestamp") {
        return true;
    }

    false
}

/// Detect multi-signature pattern
///
/// Multi-signature wallet patterns for decentralized control.
///
/// Patterns detected:
/// - Gnosis Safe pattern
/// - Required confirmations tracking
/// - execTransaction with multiple signatures
/// - Threshold checking
pub fn has_multisig_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Gnosis Safe
    if source.contains("GnosisSafe") || source.contains("Safe") {
        if source.contains("import") || source.contains("is ") {
            return true;
        }
    }

    // Pattern 2: Threshold requirement
    if source.contains("threshold") && (source.contains("require(") || source.contains("if (")) {
        if source.contains("confirmations") || source.contains("signatures") {
            return true;
        }
    }

    // Pattern 3: Confirmation tracking
    if source.contains("confirmations") && source.contains("mapping") {
        return true;
    }

    // Pattern 4: execTransaction with signature verification
    if source.contains("execTransaction") && source.contains("signatures") {
        return true;
    }

    // Pattern 5: Required signatures count
    if source.contains("requiredSignatures") || source.contains("required") {
        return true;
    }

    // Pattern 6: Multiple owners
    if source.contains("owners") && source.contains("isOwner") {
        return true;
    }

    false
}

/// Detect role hierarchy pattern
///
/// Proper role hierarchy with admin roles managing other roles.
///
/// Patterns detected:
/// - Admin role can grant/revoke other roles
/// - Role admin constants
/// - getRoleAdmin function
/// - Hierarchical permission structure
pub fn has_role_hierarchy_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: getRoleAdmin function
    if source.contains("getRoleAdmin") {
        return true;
    }

    // Pattern 2: Role admin constants
    if source.contains("_ADMIN_ROLE") {
        return true;
    }

    // Pattern 3: Multiple role levels
    let role_count = source.matches("_ROLE =").count();
    if role_count >= 2 {
        return true;
    }

    // Pattern 4: setRoleAdmin function
    if source.contains("setRoleAdmin") || source.contains("_setRoleAdmin") {
        return true;
    }

    // Pattern 5: Admin can grant role pattern
    if source.contains("onlyRole(") && source.contains("grantRole(") {
        return true;
    }

    false
}

/// Detect proper modifier usage
///
/// Functions use appropriate access control modifiers.
///
/// Patterns detected:
/// - onlyOwner on admin functions
/// - onlyRole on privileged functions
/// - whenNotPaused on state-changing functions
/// - Multiple modifiers stacked properly
pub fn has_proper_modifier_usage(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: onlyOwner on admin functions
    if source.contains("onlyOwner") {
        return true;
    }

    // Pattern 2: onlyRole modifier usage
    if source.contains("onlyRole(") {
        return true;
    }

    // Pattern 3: whenNotPaused modifier
    if source.contains("whenNotPaused") {
        return true;
    }

    // Pattern 4: nonReentrant modifier
    if source.contains("nonReentrant") {
        return true;
    }

    // Pattern 5: Custom access control modifiers
    if source.contains("modifier only") {
        return true;
    }

    false
}

/// Detect emergency pause pattern
///
/// Pausable contract pattern for emergency situations.
///
/// Patterns detected:
/// - OpenZeppelin Pausable
/// - pause() and unpause() functions
/// - whenNotPaused and whenPaused modifiers
/// - Emergency stop mechanism
pub fn has_pause_pattern(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: Pausable import/inheritance
    if source.contains("Pausable") {
        return true;
    }

    // Pattern 2: pause/unpause functions
    if source.contains("function pause()") && source.contains("function unpause()") {
        return true;
    }

    // Pattern 3: whenNotPaused modifier
    if source.contains("whenNotPaused") || source.contains("whenPaused") {
        return true;
    }

    // Pattern 4: _pause() and _unpause() internal functions
    if source.contains("_pause()") && source.contains("_unpause()") {
        return true;
    }

    // Pattern 5: paused() view function
    if source.contains("function paused()") && source.contains("returns (bool)") {
        return true;
    }

    false
}

/// Detect two-step ownership transfer
///
/// Safe ownership transfer requiring new owner acceptance.
///
/// Patterns detected:
/// - pendingOwner variable
/// - transferOwnership sets pending, doesn't transfer immediately
/// - acceptOwnership function for new owner
/// - Prevents accidental ownership loss
pub fn has_two_step_ownership(ctx: &AnalysisContext) -> bool {
    let source = &ctx.source_code;

    // Pattern 1: pendingOwner variable
    if source.contains("pendingOwner") {
        return true;
    }

    // Pattern 2: Ownable2Step
    if source.contains("Ownable2Step") {
        return true;
    }

    // Pattern 3: acceptOwnership function
    if source.contains("function acceptOwnership()") {
        return true;
    }

    // Pattern 4: transferOwnership with pending pattern
    if source.contains("transferOwnership") && source.contains("pending") {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_context(source: &str) -> AnalysisContext<'static> {
        crate::types::test_utils::create_test_context(source)
    }

    #[test]
    fn test_ownable_pattern() {
        let source = r#"
            import "@openzeppelin/contracts/access/Ownable.sol";
            contract MyContract is Ownable {
                function admin() public onlyOwner {}
            }
        "#;
        let ctx = create_context(source);
        assert!(has_ownable_pattern(&ctx));
    }

    #[test]
    fn test_access_control_pattern() {
        let source = r#"
            import "@openzeppelin/contracts/access/AccessControl.sol";
            contract MyContract is AccessControl {
                bytes32 public constant ADMIN_ROLE = keccak256("ADMIN");
                function admin() public onlyRole(ADMIN_ROLE) {}
            }
        "#;
        let ctx = create_context(source);
        assert!(has_access_control_pattern(&ctx));
    }

    #[test]
    fn test_timelock_pattern() {
        let source = r#"
            uint256 public delay = 2 days;
            mapping(bytes32 => uint256) public queuedTransactions;

            function queueTransaction(bytes32 txHash) public {
                queuedTransactions[txHash] = block.timestamp + delay;
            }

            function executeTransaction(bytes32 txHash) public {
                require(block.timestamp >= queuedTransactions[txHash]);
            }
        "#;
        let ctx = create_context(source);
        assert!(has_timelock_pattern(&ctx));
    }

    #[test]
    fn test_multisig_pattern() {
        let source = r#"
            uint256 public threshold = 3;
            mapping(address => bool) public isOwner;
            mapping(bytes32 => uint256) public confirmations;

            function execTransaction(bytes32 txHash, bytes[] memory signatures) public {
                require(signatures.length >= threshold);
            }
        "#;
        let ctx = create_context(source);
        assert!(has_multisig_pattern(&ctx));
    }

    #[test]
    fn test_two_step_ownership() {
        let source = r#"
            address public owner;
            address public pendingOwner;

            function transferOwnership(address newOwner) public onlyOwner {
                pendingOwner = newOwner;
            }

            function acceptOwnership() public {
                require(msg.sender == pendingOwner);
                owner = pendingOwner;
                pendingOwner = address(0);
            }
        "#;
        let ctx = create_context(source);
        assert!(has_two_step_ownership(&ctx));
    }
}
