use anyhow::Result;

use detectors::{
    Detector, DetectorId, Finding, Severity, Confidence, AnalysisContext,
    logic::{DivisionOrderDetector, StateMachineDetector}
};
use ast::Contract;
use cfg::ControlFlowGraph;
use dataflow::{DataFlowAnalysis, TaintAnalysis};
use semantic::SymbolTable;

#[test]
fn test_division_before_multiplication_vulnerable() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract VulnerableMath {
            uint256 public constant PRECISION = 1e18;
            uint256 public rate = 150; // 1.5% in basis points

            // VULNERABILITY: Division before multiplication causes precision loss
            function calculateReward(uint256 amount) public view returns (uint256) {
                // Wrong order: division first, then multiplication
                return (amount / 100) * rate;
            }

            // VULNERABILITY: Multiple divisions compound precision loss
            function complexCalculation(uint256 principal, uint256 days) public pure returns (uint256) {
                uint256 dailyRate = 500; // 5% daily
                // Multiple divisions before multiplication
                return (principal / 365) / 100 * dailyRate * days;
            }

            // VULNERABILITY: Division in loop compounds error
            function compoundingInterest(uint256 amount, uint256 periods) public pure returns (uint256) {
                uint256 result = amount;
                for (uint256 i = 0; i < periods; i++) {
                    // Division before multiplication in each iteration
                    result = (result / 100) * 105; // 5% increase
                }
                return result;
            }

            // VULNERABILITY: Fee calculation with precision loss
            function calculateFee(uint256 transactionAmount) public pure returns (uint256) {
                uint256 feeRate = 25; // 0.25%
                // Division before multiplication loses precision
                return (transactionAmount / 10000) * feeRate;
            }

            // VULNERABILITY: Token swap with poor precision
            function swapTokens(uint256 inputAmount, uint256 inputPrice, uint256 outputPrice)
                public pure returns (uint256) {
                // Division first loses precision
                return (inputAmount / inputPrice) * outputPrice;
            }

            // VULNERABILITY: Yield calculation
            function calculateYield(uint256 stakedAmount, uint256 stakingDays)
                public pure returns (uint256) {
                uint256 annualYield = 1000; // 10%
                // Division before multiplication
                return (stakedAmount / 365) * annualYield * stakingDays / 100;
            }

            // Correct implementation for comparison
            function calculateRewardCorrect(uint256 amount) public view returns (uint256) {
                // Correct order: multiplication first, then division
                return (amount * rate) / 100;
            }
        }
    "#;

    let detector = DivisionOrderDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect multiple division-before-multiplication issues
    assert!(findings.len() >= 5);

    // Verify calculateReward vulnerability
    let reward_finding = findings.iter()
        .find(|f| f.message.contains("calculateReward"))
        .expect("Should detect calculateReward division issue");
    assert_eq!(reward_finding.severity, Severity::Medium);
    assert!(reward_finding.message.contains("division before multiplication"));

    // Verify complex calculation vulnerability
    let complex_finding = findings.iter()
        .find(|f| f.message.contains("complexCalculation"))
        .expect("Should detect complex calculation issue");
    assert!(complex_finding.severity >= Severity::Medium);

    // Verify fee calculation vulnerability
    let fee_finding = findings.iter()
        .find(|f| f.message.contains("calculateFee"))
        .expect("Should detect fee calculation issue");
    assert!(fee_finding.message.contains("precision loss"));
}

#[test]
fn test_division_before_multiplication_secure() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract SecureMath {
            uint256 public constant PRECISION = 1e18;
            uint256 public rate = 150;

            // SECURE: Multiplication before division
            function calculateReward(uint256 amount) public view returns (uint256) {
                return (amount * rate) / 100;
            }

            // SECURE: Using higher precision first
            function complexCalculation(uint256 principal, uint256 days) public pure returns (uint256) {
                uint256 dailyRate = 500;
                // Multiply first to maintain precision
                return (principal * dailyRate * days) / (365 * 100);
            }

            // SECURE: Fixed-point arithmetic
            function preciseCalculation(uint256 amount) public pure returns (uint256) {
                uint256 rate = 150 * PRECISION / 10000; // Convert to fixed point
                return (amount * rate) / PRECISION;
            }

            // SECURE: Using libraries for precision
            function safeCalculation(uint256 amount) public pure returns (uint256) {
                // Simulating a safe math library approach
                return mulDiv(amount, 150, 10000);
            }

            function mulDiv(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
                return (a * b) / c;
            }
        }
    "#;

    let detector = DivisionOrderDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should not detect issues in secure implementation
    assert_eq!(findings.len(), 0);
}

#[test]
fn test_state_machine_vulnerabilities() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract VulnerableStateMachine {
            enum State { Inactive, Active, Paused, Terminated }
            State public currentState = State.Inactive;

            mapping(address => uint256) public balances;
            address public owner;

            modifier onlyOwner() {
                require(msg.sender == owner, "Only owner");
                _;
            }

            constructor() {
                owner = msg.sender;
            }

            // VULNERABILITY: Missing state validation
            function activate() public {
                // Should check if state is Inactive
                currentState = State.Active;
            }

            // VULNERABILITY: Invalid state transition
            function forceTerminate() public onlyOwner {
                // Direct transition from any state to Terminated without validation
                currentState = State.Terminated;
            }

            // VULNERABILITY: Operations allowed in wrong state
            function deposit() public payable {
                // Should only work in Active state
                balances[msg.sender] += msg.value;
            }

            // VULNERABILITY: State change without proper checks
            function pause() public onlyOwner {
                // Should only pause if active
                currentState = State.Paused;
            }

            // VULNERABILITY: Resume without validation
            function resume() public onlyOwner {
                // Should only resume from paused state
                currentState = State.Active;
            }

            // VULNERABILITY: Withdrawal in wrong state
            function withdraw(uint256 amount) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                // Should check if contract is in Active state
                balances[msg.sender] -= amount;
                payable(msg.sender).transfer(amount);
            }

            // VULNERABILITY: Emergency function callable in wrong state
            function emergencyWithdraw() public {
                // Should only work when Terminated
                uint256 balance = balances[msg.sender];
                balances[msg.sender] = 0;
                payable(msg.sender).transfer(balance);
            }

            // VULNERABILITY: State transition race condition
            function complexOperation() public {
                require(currentState == State.Active, "Must be active");

                // Long operation that could be front-run
                _doComplexWork();

                // State might have changed during execution
                balances[msg.sender] += 100;
            }

            function _doComplexWork() internal {
                // Simulate complex operation
                for (uint i = 0; i < 100; i++) {
                    // Work that takes time
                }
            }
        }
    "#;

    let detector = StateMachineDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect multiple state machine vulnerabilities
    assert!(findings.len() >= 6);

    // Verify missing state validation
    let activation_finding = findings.iter()
        .find(|f| f.message.contains("activate"))
        .expect("Should detect activation without state check");
    assert!(activation_finding.severity >= Severity::Medium);

    // Verify invalid state transition
    let force_terminate_finding = findings.iter()
        .find(|f| f.message.contains("forceTerminate"))
        .expect("Should detect invalid state transition");
    assert!(force_terminate_finding.message.contains("state transition"));

    // Verify operations in wrong state
    let deposit_finding = findings.iter()
        .find(|f| f.message.contains("deposit"))
        .expect("Should detect operation without state check");
    assert!(deposit_finding.message.contains("state validation"));
}

#[test]
fn test_state_machine_secure() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract SecureStateMachine {
            enum State { Inactive, Active, Paused, Terminated }
            State public currentState = State.Inactive;

            mapping(address => uint256) public balances;
            address public owner;

            modifier onlyOwner() {
                require(msg.sender == owner, "Only owner");
                _;
            }

            modifier onlyInState(State _state) {
                require(currentState == _state, "Invalid state");
                _;
            }

            modifier validTransition(State _from, State _to) {
                require(currentState == _from, "Invalid current state");
                require(_isValidTransition(_from, _to), "Invalid transition");
                _;
            }

            constructor() {
                owner = msg.sender;
            }

            // SECURE: Proper state validation
            function activate() public onlyOwner onlyInState(State.Inactive) {
                currentState = State.Active;
            }

            // SECURE: Controlled state transitions
            function pause() public onlyOwner validTransition(State.Active, State.Paused) {
                currentState = State.Paused;
            }

            function resume() public onlyOwner validTransition(State.Paused, State.Active) {
                currentState = State.Active;
            }

            function terminate() public onlyOwner {
                require(currentState != State.Terminated, "Already terminated");
                currentState = State.Terminated;
            }

            // SECURE: Operations with state checks
            function deposit() public payable onlyInState(State.Active) {
                balances[msg.sender] += msg.value;
            }

            function withdraw(uint256 amount) public onlyInState(State.Active) {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                balances[msg.sender] -= amount;
                payable(msg.sender).transfer(amount);
            }

            function emergencyWithdraw() public onlyInState(State.Terminated) {
                uint256 balance = balances[msg.sender];
                balances[msg.sender] = 0;
                payable(msg.sender).transfer(balance);
            }

            // SECURE: Atomic state operations
            function secureComplexOperation() public onlyInState(State.Active) {
                // Use a temporary state or lock to prevent race conditions
                State originalState = currentState;
                currentState = State.Paused; // Temporarily pause

                _doComplexWork();

                currentState = originalState; // Restore state
                balances[msg.sender] += 100;
            }

            function _isValidTransition(State _from, State _to) internal pure returns (bool) {
                // Define valid state transitions
                if (_from == State.Inactive && _to == State.Active) return true;
                if (_from == State.Active && _to == State.Paused) return true;
                if (_from == State.Paused && _to == State.Active) return true;
                if (_from != State.Terminated && _to == State.Terminated) return true;
                return false;
            }

            function _doComplexWork() internal {
                // Complex work implementation
            }
        }
    "#;

    let detector = StateMachineDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should not detect issues in secure implementation
    assert_eq!(findings.len(), 0);
}

#[test]
fn test_complex_logic_errors() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract ComplexLogicErrors {
            mapping(address => uint256) public balances;
            mapping(address => uint256) public lastUpdate;
            uint256 public totalSupply;

            // VULNERABILITY: Logic error in calculation
            function calculateCompoundInterest(uint256 principal, uint256 rate, uint256 time)
                public pure returns (uint256) {
                // Wrong: Should use compound formula, not simple interest
                return principal + (principal * rate * time / 100);
            }

            // VULNERABILITY: Off-by-one error
            function processArray(uint256[] memory values) public pure returns (uint256) {
                uint256 sum = 0;
                // Off-by-one: should be < values.length
                for (uint256 i = 0; i <= values.length; i++) {
                    sum += values[i];
                }
                return sum;
            }

            // VULNERABILITY: Logic error in conditional
            function checkEligibility(address user, uint256 amount) public view returns (bool) {
                // Logic error: should be OR, not AND
                return balances[user] > amount && lastUpdate[user] > block.timestamp;
            }

            // VULNERABILITY: Incorrect boundary condition
            function distributeRewards(address[] memory users, uint256 totalReward) public {
                uint256 rewardPerUser = totalReward / users.length;

                // Logic error: ignores remainder
                for (uint256 i = 0; i < users.length; i++) {
                    balances[users[i]] += rewardPerUser;
                    totalSupply += rewardPerUser; // This will be less than totalReward
                }
            }

            // VULNERABILITY: Inconsistent state updates
            function transfer(address to, uint256 amount) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");

                balances[msg.sender] -= amount;
                balances[to] += amount;

                // Logic error: forgetting to update totalSupply tracking
                // (if this contract tracks total user balances)
            }

            // VULNERABILITY: Wrong comparison operator
            function isExpired(uint256 deadline) public view returns (bool) {
                // Logic error: should be >=, not >
                return block.timestamp > deadline;
            }

            // VULNERABILITY: Incorrect loop bounds
            function batchProcess(uint256 startId, uint256 endId) public {
                // Logic error: should be <= endId to include endId
                for (uint256 id = startId; id < endId; id++) {
                    _processItem(id);
                }
            }

            function _processItem(uint256 id) internal {
                // Processing logic
            }
        }
    "#;

    let detector = DivisionOrderDetector::new(); // This would be expanded to LogicErrorDetector
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect various logic errors
    assert!(findings.len() >= 3); // At least some detectable issues

    // The detector would need to be enhanced to catch more complex logic errors
    // For now, it might only catch division-before-multiplication issues
}

// Helper functions for test setup
fn parse_contract(solidity_code: &str) -> Result<Contract> {
    // This would use the actual parser implementation
    // For now, return a placeholder that will cause tests to fail
    unimplemented!("Contract parsing not yet implemented - tests should fail initially")
}

fn create_analysis_context(contract: &Contract) -> AnalysisContext {
    // This would create a real analysis context with CFG, data flow, etc.
    // For now, return a placeholder that will cause tests to fail
    unimplemented!("Analysis context creation not yet implemented - tests should fail initially")
}

// Additional test helper functions
fn assert_finding_has_logic_cwe(finding: &Finding) {
    // CWE-682: Incorrect Calculation
    // CWE-193: Off-by-one Error
    assert!(finding.cwe_ids.contains(&682) || finding.cwe_ids.contains(&193));
}

#[test]
fn test_integer_overflow_logic() {
    let solidity_code = r#"
        pragma solidity ^0.7.0; // Older version without automatic overflow checks

        contract OverflowLogic {
            mapping(address => uint256) public balances;

            // VULNERABILITY: Potential overflow in calculation
            function calculateReward(uint256 amount, uint256 multiplier) public pure returns (uint256) {
                // Could overflow if amount * multiplier > 2^256
                return amount * multiplier;
            }

            // VULNERABILITY: Unchecked addition
            function addBalance(address user, uint256 amount) public {
                // Could overflow
                balances[user] += amount;
            }

            // VULNERABILITY: Subtraction underflow
            function subtractBalance(address user, uint256 amount) public {
                // Could underflow if amount > balances[user]
                balances[user] -= amount;
            }
        }
    "#;

    let detector = DivisionOrderDetector::new(); // Would be expanded to include overflow detection
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // For Solidity < 0.8.0, should detect potential overflow issues
    // Current detector might not catch these, but enhanced version would
}

#[test]
fn test_race_condition_logic() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract RaceConditionLogic {
            mapping(address => uint256) public balances;
            mapping(address => bool) public processed;

            // VULNERABILITY: Race condition in check-then-act pattern
            function processUser(address user) public {
                require(!processed[user], "Already processed");

                // Race condition: another transaction could process the same user
                // between the check and the state update
                _doProcessing(user);

                processed[user] = true;
            }

            // VULNERABILITY: Non-atomic operations
            function transferBatch(address[] memory recipients, uint256[] memory amounts) public {
                for (uint256 i = 0; i < recipients.length; i++) {
                    require(balances[msg.sender] >= amounts[i], "Insufficient balance");

                    // Non-atomic: balance could change between check and transfer
                    balances[msg.sender] -= amounts[i];
                    balances[recipients[i]] += amounts[i];
                }
            }

            function _doProcessing(address user) internal {
                balances[user] += 1000;
            }
        }
    "#;

    let detector = StateMachineDetector::new(); // Could be enhanced to detect race conditions
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect race conditions and non-atomic operations
    // Current implementation might not catch all of these
}