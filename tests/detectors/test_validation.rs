use anyhow::Result;

use detectors::{
    Detector, DetectorId, Finding, Severity, Confidence, AnalysisContext,
    validation::{ZeroAddressDetector, ArrayBoundsDetector, ParameterCheckDetector}
};
use ast::Contract;
use cfg::ControlFlowGraph;
use dataflow::{DataFlowAnalysis, TaintAnalysis};
use semantic::SymbolTable;

#[test]
fn test_zero_address_vulnerabilities() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract VulnerableZeroAddress {
            address public owner;
            address public treasury;
            mapping(address => uint256) public balances;

            constructor(address _owner, address _treasury) {
                // VULNERABILITY: No zero address check
                owner = _owner;
                treasury = _treasury;
            }

            // VULNERABILITY: Missing zero address validation
            function setOwner(address newOwner) public {
                require(msg.sender == owner, "Only owner");
                // Should check newOwner != address(0)
                owner = newOwner;
            }

            // VULNERABILITY: Transfer to zero address
            function transfer(address to, uint256 amount) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                // Should check to != address(0)
                balances[msg.sender] -= amount;
                balances[to] += amount;
            }

            // VULNERABILITY: Approve zero address
            mapping(address => mapping(address => uint256)) public allowances;

            function approve(address spender, uint256 amount) public {
                // Should check spender != address(0)
                allowances[msg.sender][spender] = amount;
            }

            // VULNERABILITY: Zero address in array operations
            function batchTransfer(address[] memory recipients, uint256[] memory amounts) public {
                require(recipients.length == amounts.length, "Length mismatch");

                for (uint256 i = 0; i < recipients.length; i++) {
                    // Should validate each recipient != address(0)
                    require(balances[msg.sender] >= amounts[i], "Insufficient balance");
                    balances[msg.sender] -= amounts[i];
                    balances[recipients[i]] += amounts[i];
                }
            }

            // VULNERABILITY: External call to zero address
            function callExternal(address target, bytes calldata data) public {
                require(msg.sender == owner, "Only owner");
                // Should check target != address(0)
                (bool success,) = target.call(data);
                require(success, "Call failed");
            }

            // VULNERABILITY: Delegate call to zero address
            function delegateCallExternal(address target, bytes calldata data) public {
                require(msg.sender == owner, "Only owner");
                // Should check target != address(0)
                (bool success,) = target.delegatecall(data);
                require(success, "Delegate call failed");
            }

            // VULNERABILITY: Setting contract addresses without validation
            address public tokenContract;
            address public oracleContract;

            function setContracts(address _token, address _oracle) public {
                require(msg.sender == owner, "Only owner");
                // Should validate both addresses
                tokenContract = _token;
                oracleContract = _oracle;
            }

            // VULNERABILITY: Reward distribution to zero address
            function distributeReward(address recipient, uint256 amount) public {
                // Should check recipient != address(0)
                balances[recipient] += amount;
            }

            // VULNERABILITY: Emergency withdrawal to zero address
            function emergencyWithdraw(address recipient) public {
                require(msg.sender == owner, "Only owner");
                // Should check recipient != address(0)
                uint256 balance = address(this).balance;
                payable(recipient).transfer(balance);
            }
        }
    "#;

    let detector = ZeroAddressDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect multiple zero address vulnerabilities
    assert!(findings.len() >= 8);

    // Verify constructor parameter issue
    let constructor_finding = findings.iter()
        .find(|f| f.message.contains("constructor") || f.message.contains("_owner"))
        .expect("Should detect constructor zero address issue");
    assert!(constructor_finding.severity >= Severity::Medium);

    // Verify setOwner vulnerability
    let set_owner_finding = findings.iter()
        .find(|f| f.message.contains("setOwner"))
        .expect("Should detect setOwner zero address issue");
    assert!(set_owner_finding.message.contains("zero address"));

    // Verify transfer vulnerability
    let transfer_finding = findings.iter()
        .find(|f| f.message.contains("transfer"))
        .expect("Should detect transfer zero address issue");
    assert_eq!(transfer_finding.severity, Severity::High);

    // Verify external call vulnerability
    let call_finding = findings.iter()
        .find(|f| f.message.contains("callExternal"))
        .expect("Should detect external call zero address issue");
    assert!(call_finding.severity >= Severity::Medium);
}

#[test]
fn test_zero_address_secure() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract SecureZeroAddress {
            address public owner;
            address public treasury;
            mapping(address => uint256) public balances;

            error ZeroAddressNotAllowed();

            modifier notZeroAddress(address addr) {
                if (addr == address(0)) revert ZeroAddressNotAllowed();
                _;
            }

            constructor(address _owner, address _treasury)
                notZeroAddress(_owner)
                notZeroAddress(_treasury) {
                owner = _owner;
                treasury = _treasury;
            }

            // SECURE: Proper zero address validation
            function setOwner(address newOwner) public notZeroAddress(newOwner) {
                require(msg.sender == owner, "Only owner");
                owner = newOwner;
            }

            function transfer(address to, uint256 amount) public notZeroAddress(to) {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                balances[msg.sender] -= amount;
                balances[to] += amount;
            }

            function approve(address spender, uint256 amount) public notZeroAddress(spender) {
                allowances[msg.sender][spender] = amount;
            }

            mapping(address => mapping(address => uint256)) public allowances;

            // SECURE: Validate array elements
            function batchTransfer(address[] memory recipients, uint256[] memory amounts) public {
                require(recipients.length == amounts.length, "Length mismatch");

                for (uint256 i = 0; i < recipients.length; i++) {
                    require(recipients[i] != address(0), "Zero address recipient");
                    require(balances[msg.sender] >= amounts[i], "Insufficient balance");
                    balances[msg.sender] -= amounts[i];
                    balances[recipients[i]] += amounts[i];
                }
            }

            // SECURE: External call validation
            function callExternal(address target, bytes calldata data) public notZeroAddress(target) {
                require(msg.sender == owner, "Only owner");
                (bool success,) = target.call(data);
                require(success, "Call failed");
            }

            // SECURE: Contract address validation
            address public tokenContract;
            address public oracleContract;

            function setContracts(address _token, address _oracle) public
                notZeroAddress(_token)
                notZeroAddress(_oracle) {
                require(msg.sender == owner, "Only owner");
                tokenContract = _token;
                oracleContract = _oracle;
            }
        }
    "#;

    let detector = ZeroAddressDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should not detect issues in secure implementation
    assert_eq!(findings.len(), 0);
}

#[test]
fn test_array_bounds_vulnerabilities() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract VulnerableArrayBounds {
            uint256[] public values;
            mapping(uint256 => uint256) public data;

            // VULNERABILITY: No bounds checking
            function getValue(uint256 index) public view returns (uint256) {
                // Should check index < values.length
                return values[index];
            }

            // VULNERABILITY: Off-by-one error
            function processArray() public view returns (uint256) {
                uint256 sum = 0;
                // Wrong condition: should be < values.length
                for (uint256 i = 0; i <= values.length; i++) {
                    sum += values[i];
                }
                return sum;
            }

            // VULNERABILITY: Unchecked array access in loop
            function batchUpdate(uint256[] memory indices, uint256[] memory newValues) public {
                for (uint256 i = 0; i < indices.length; i++) {
                    // Should validate indices[i] < values.length
                    values[indices[i]] = newValues[i];
                }
            }

            // VULNERABILITY: Dynamic array access without bounds check
            function getElementAt(uint256 index) public view returns (uint256) {
                // Direct access without validation
                return values[index];
            }

            // VULNERABILITY: Negative index (underflow)
            function getPrevious(uint256 index) public view returns (uint256) {
                // Could underflow if index is 0
                return values[index - 1];
            }

            // VULNERABILITY: Array access in external call
            function externalArrayAccess(address target, uint256 index) public {
                bytes memory data = abi.encodeWithSignature("process(uint256)", values[index]);
                (bool success,) = target.call(data);
                require(success, "External call failed");
            }

            // VULNERABILITY: Multi-dimensional array access
            uint256[][] public matrix;

            function getMatrixValue(uint256 row, uint256 col) public view returns (uint256) {
                // Should check both row and col bounds
                return matrix[row][col];
            }

            // VULNERABILITY: Array slice without validation
            function getSlice(uint256 start, uint256 end) public view returns (uint256[] memory) {
                uint256[] memory result = new uint256[](end - start);
                for (uint256 i = start; i < end; i++) {
                    // Should validate i < values.length
                    result[i - start] = values[i];
                }
                return result;
            }

            // VULNERABILITY: String/bytes array access
            string[] public messages;

            function getMessage(uint256 index) public view returns (string memory) {
                // Should validate index
                return messages[index];
            }

            // VULNERABILITY: Struct array access
            struct User {
                address addr;
                uint256 balance;
            }

            User[] public users;

            function getUser(uint256 index) public view returns (User memory) {
                // Should validate index
                return users[index];
            }
        }
    "#;

    let detector = ArrayBoundsDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect multiple array bounds issues
    assert!(findings.len() >= 7);

    // Verify direct array access issue
    let get_value_finding = findings.iter()
        .find(|f| f.message.contains("getValue"))
        .expect("Should detect getValue bounds issue");
    assert!(get_value_finding.severity >= Severity::Medium);

    // Verify off-by-one error
    let process_finding = findings.iter()
        .find(|f| f.message.contains("processArray"))
        .expect("Should detect off-by-one error");
    assert!(process_finding.message.contains("bounds") || process_finding.message.contains("off-by-one"));

    // Verify batch update issue
    let batch_finding = findings.iter()
        .find(|f| f.message.contains("batchUpdate"))
        .expect("Should detect batch update bounds issue");
    assert_eq!(batch_finding.severity, Severity::High);

    // Verify matrix access issue
    let matrix_finding = findings.iter()
        .find(|f| f.message.contains("getMatrixValue"))
        .expect("Should detect matrix bounds issue");
    assert!(matrix_finding.message.contains("multi-dimensional") || matrix_finding.message.contains("bounds"));
}

#[test]
fn test_array_bounds_secure() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract SecureArrayBounds {
            uint256[] public values;

            error IndexOutOfBounds(uint256 index, uint256 length);

            modifier validIndex(uint256 index) {
                if (index >= values.length) revert IndexOutOfBounds(index, values.length);
                _;
            }

            // SECURE: Proper bounds checking
            function getValue(uint256 index) public view validIndex(index) returns (uint256) {
                return values[index];
            }

            function safeGetValue(uint256 index) public view returns (uint256) {
                require(index < values.length, "Index out of bounds");
                return values[index];
            }

            // SECURE: Correct loop bounds
            function processArray() public view returns (uint256) {
                uint256 sum = 0;
                for (uint256 i = 0; i < values.length; i++) {
                    sum += values[i];
                }
                return sum;
            }

            // SECURE: Validate all indices
            function batchUpdate(uint256[] memory indices, uint256[] memory newValues) public {
                require(indices.length == newValues.length, "Length mismatch");

                for (uint256 i = 0; i < indices.length; i++) {
                    require(indices[i] < values.length, "Index out of bounds");
                    values[indices[i]] = newValues[i];
                }
            }

            // SECURE: Safe previous element access
            function getPrevious(uint256 index) public view returns (uint256) {
                require(index > 0 && index < values.length, "Invalid index");
                return values[index - 1];
            }

            // SECURE: Multi-dimensional array with validation
            uint256[][] public matrix;

            function getMatrixValue(uint256 row, uint256 col) public view returns (uint256) {
                require(row < matrix.length, "Row out of bounds");
                require(col < matrix[row].length, "Column out of bounds");
                return matrix[row][col];
            }

            // SECURE: Array slice with validation
            function getSlice(uint256 start, uint256 end) public view returns (uint256[] memory) {
                require(start <= end, "Invalid range");
                require(end <= values.length, "End index out of bounds");

                uint256[] memory result = new uint256[](end - start);
                for (uint256 i = start; i < end; i++) {
                    result[i - start] = values[i];
                }
                return result;
            }

            // SECURE: Try-catch for safe access
            function tryGetValue(uint256 index) public view returns (bool success, uint256 value) {
                if (index >= values.length) {
                    return (false, 0);
                }
                return (true, values[index]);
            }
        }
    "#;

    let detector = ArrayBoundsDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should not detect issues in secure implementation
    assert_eq!(findings.len(), 0);
}

#[test]
fn test_parameter_consistency_vulnerabilities() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract VulnerableParameterCheck {
            mapping(address => uint256) public balances;

            // VULNERABILITY: Array length mismatch not checked
            function batchTransfer(
                address[] memory recipients,
                uint256[] memory amounts
            ) public {
                // Should check recipients.length == amounts.length
                for (uint256 i = 0; i < recipients.length; i++) {
                    require(balances[msg.sender] >= amounts[i], "Insufficient balance");
                    balances[msg.sender] -= amounts[i];
                    balances[recipients[i]] += amounts[i];
                }
            }

            // VULNERABILITY: Parameter ranges not validated
            function setInterestRate(uint256 rate) public {
                // Should validate rate is within reasonable bounds (e.g., 0-10000 basis points)
                interestRate = rate;
            }

            uint256 public interestRate;

            // VULNERABILITY: Inconsistent parameter validation
            function processPayment(
                address from,
                address to,
                uint256 amount,
                uint256 fee
            ) public {
                require(from != address(0), "Invalid from address");
                // Missing validation for 'to' address
                require(amount > 0, "Amount must be positive");
                // Missing validation for 'fee'

                balances[from] -= (amount + fee);
                balances[to] += amount;
            }

            // VULNERABILITY: Missing zero amount check
            function deposit() public payable {
                // Should check msg.value > 0
                balances[msg.sender] += msg.value;
            }

            // VULNERABILITY: Percentage parameter without bounds
            function calculateFee(uint256 amount, uint256 percentage) public pure returns (uint256) {
                // Should validate percentage <= 100 (or 10000 for basis points)
                return (amount * percentage) / 100;
            }

            // VULNERABILITY: Time parameter without validation
            function setLockPeriod(uint256 lockTime) public {
                // Should validate lockTime is reasonable (not too short/long)
                lockPeriod = lockTime;
            }

            uint256 public lockPeriod;

            // VULNERABILITY: Multiple arrays without length consistency
            function updateMultipleData(
                uint256[] memory ids,
                string[] memory names,
                uint256[] memory values,
                address[] memory owners
            ) public {
                // Should validate all arrays have same length
                for (uint256 i = 0; i < ids.length; i++) {
                    // This will fail if arrays have different lengths
                    emit DataUpdated(ids[i], names[i], values[i], owners[i]);
                }
            }

            event DataUpdated(uint256 id, string name, uint256 value, address owner);

            // VULNERABILITY: Missing parameter normalization
            function transferTokens(
                address token,
                address to,
                uint256 amount,
                uint8 decimals
            ) public {
                // Should normalize amount based on token decimals
                // Different tokens have different decimal places
                IERC20(token).transfer(to, amount);
            }

            // VULNERABILITY: Enum parameter without validation
            enum ActionType { Deposit, Withdraw, Transfer }

            function executeAction(ActionType action, uint256 amount) public {
                // Should validate action is within enum range
                if (action == ActionType.Deposit) {
                    balances[msg.sender] += amount;
                } else if (action == ActionType.Withdraw) {
                    balances[msg.sender] -= amount;
                }
                // Missing Transfer case
            }

            // VULNERABILITY: String parameter without validation
            function setUserName(string memory name) public {
                // Should validate name length and content
                userNames[msg.sender] = name;
            }

            mapping(address => string) public userNames;
        }

        interface IERC20 {
            function transfer(address to, uint256 amount) external returns (bool);
        }
    "#;

    let detector = ParameterCheckDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect multiple parameter validation issues
    assert!(findings.len() >= 8);

    // Verify array length mismatch
    let batch_finding = findings.iter()
        .find(|f| f.message.contains("batchTransfer"))
        .expect("Should detect array length mismatch");
    assert!(batch_finding.message.contains("length") || batch_finding.message.contains("consistency"));

    // Verify parameter range validation
    let rate_finding = findings.iter()
        .find(|f| f.message.contains("setInterestRate"))
        .expect("Should detect missing range validation");
    assert!(rate_finding.severity >= Severity::Medium);

    // Verify inconsistent validation
    let payment_finding = findings.iter()
        .find(|f| f.message.contains("processPayment"))
        .expect("Should detect inconsistent parameter validation");
    assert!(payment_finding.message.contains("validation") || payment_finding.message.contains("consistency"));

    // Verify zero amount check
    let deposit_finding = findings.iter()
        .find(|f| f.message.contains("deposit"))
        .expect("Should detect missing zero amount check");
    assert!(deposit_finding.message.contains("zero") || deposit_finding.message.contains("amount"));
}

#[test]
fn test_parameter_consistency_secure() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract SecureParameterCheck {
            mapping(address => uint256) public balances;

            error InvalidParameters(string reason);
            error ArrayLengthMismatch(uint256 length1, uint256 length2);

            // SECURE: Proper array length validation
            function batchTransfer(
                address[] memory recipients,
                uint256[] memory amounts
            ) public {
                if (recipients.length != amounts.length) {
                    revert ArrayLengthMismatch(recipients.length, amounts.length);
                }

                for (uint256 i = 0; i < recipients.length; i++) {
                    require(recipients[i] != address(0), "Invalid recipient");
                    require(amounts[i] > 0, "Amount must be positive");
                    require(balances[msg.sender] >= amounts[i], "Insufficient balance");

                    balances[msg.sender] -= amounts[i];
                    balances[recipients[i]] += amounts[i];
                }
            }

            // SECURE: Parameter range validation
            uint256 public interestRate;
            uint256 public constant MAX_INTEREST_RATE = 1000; // 10% in basis points

            function setInterestRate(uint256 rate) public {
                require(rate <= MAX_INTEREST_RATE, "Interest rate too high");
                interestRate = rate;
            }

            // SECURE: Comprehensive parameter validation
            function processPayment(
                address from,
                address to,
                uint256 amount,
                uint256 fee
            ) public {
                require(from != address(0), "Invalid from address");
                require(to != address(0), "Invalid to address");
                require(amount > 0, "Amount must be positive");
                require(fee <= amount / 10, "Fee too high"); // Max 10% fee
                require(balances[from] >= amount + fee, "Insufficient balance");

                balances[from] -= (amount + fee);
                balances[to] += amount;
            }

            // SECURE: Zero amount validation
            function deposit() public payable {
                require(msg.value > 0, "Deposit amount must be positive");
                balances[msg.sender] += msg.value;
            }

            // SECURE: Percentage bounds validation
            function calculateFee(uint256 amount, uint256 percentage) public pure returns (uint256) {
                require(percentage <= 100, "Percentage cannot exceed 100");
                return (amount * percentage) / 100;
            }

            // SECURE: Time parameter validation
            uint256 public lockPeriod;
            uint256 public constant MIN_LOCK_PERIOD = 1 days;
            uint256 public constant MAX_LOCK_PERIOD = 365 days;

            function setLockPeriod(uint256 lockTime) public {
                require(lockTime >= MIN_LOCK_PERIOD, "Lock period too short");
                require(lockTime <= MAX_LOCK_PERIOD, "Lock period too long");
                lockPeriod = lockTime;
            }

            // SECURE: Multiple array consistency validation
            function updateMultipleData(
                uint256[] memory ids,
                string[] memory names,
                uint256[] memory values,
                address[] memory owners
            ) public {
                require(ids.length == names.length, "IDs and names length mismatch");
                require(names.length == values.length, "Names and values length mismatch");
                require(values.length == owners.length, "Values and owners length mismatch");

                for (uint256 i = 0; i < ids.length; i++) {
                    require(ids[i] > 0, "Invalid ID");
                    require(bytes(names[i]).length > 0, "Empty name");
                    require(owners[i] != address(0), "Invalid owner");

                    emit DataUpdated(ids[i], names[i], values[i], owners[i]);
                }
            }

            event DataUpdated(uint256 id, string name, uint256 value, address owner);

            // SECURE: Enum validation
            enum ActionType { Deposit, Withdraw, Transfer }

            function executeAction(ActionType action, uint256 amount) public {
                require(amount > 0, "Amount must be positive");

                if (action == ActionType.Deposit) {
                    balances[msg.sender] += amount;
                } else if (action == ActionType.Withdraw) {
                    require(balances[msg.sender] >= amount, "Insufficient balance");
                    balances[msg.sender] -= amount;
                } else if (action == ActionType.Transfer) {
                    // Transfer logic would go here
                    require(balances[msg.sender] >= amount, "Insufficient balance");
                } else {
                    revert InvalidParameters("Invalid action type");
                }
            }

            // SECURE: String validation
            mapping(address => string) public userNames;
            uint256 public constant MAX_NAME_LENGTH = 50;

            function setUserName(string memory name) public {
                require(bytes(name).length > 0, "Name cannot be empty");
                require(bytes(name).length <= MAX_NAME_LENGTH, "Name too long");

                // Additional validation for valid characters could be added
                userNames[msg.sender] = name;
            }
        }
    "#;

    let detector = ParameterCheckDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should not detect issues in secure implementation
    assert_eq!(findings.len(), 0);
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
fn assert_finding_has_validation_cwe(finding: &Finding) {
    // CWE-20: Improper Input Validation
    // CWE-129: Improper Validation of Array Index
    // CWE-190: Integer Overflow or Wraparound
    assert!(finding.cwe_ids.contains(&20) ||
            finding.cwe_ids.contains(&129) ||
            finding.cwe_ids.contains(&190));
}

#[test]
fn test_complex_validation_patterns() {
    let solidity_code = r#"
        pragma solidity ^0.8.0;

        contract ComplexValidation {
            struct TokenInfo {
                address tokenAddress;
                uint256 decimals;
                uint256 minAmount;
                uint256 maxAmount;
            }

            mapping(address => TokenInfo) public supportedTokens;

            // VULNERABILITY: Complex parameter interdependencies not validated
            function swapTokens(
                address tokenIn,
                address tokenOut,
                uint256 amountIn,
                uint256 minAmountOut,
                uint256 deadline
            ) public {
                // Missing validations:
                // 1. tokenIn != tokenOut
                // 2. Both tokens are supported
                // 3. amountIn within token limits
                // 4. deadline > block.timestamp
                // 5. minAmountOut reasonable compared to amountIn

                TokenInfo memory inToken = supportedTokens[tokenIn];
                TokenInfo memory outToken = supportedTokens[tokenOut];

                // Logic continues without proper validation
            }

            // VULNERABILITY: Bitwise operation parameters not validated
            function setBitFlags(uint256 flags, uint8 position, bool value) public {
                // Should validate position < 256 for uint256
                if (value) {
                    flags |= (1 << position);
                } else {
                    flags &= ~(1 << position);
                }
            }

            // VULNERABILITY: Recursive call depth not validated
            function processRecursive(uint256[] memory data, uint256 depth) public {
                // Should limit recursion depth
                if (depth > 0) {
                    // Process current level
                    for (uint256 i = 0; i < data.length; i++) {
                        data[i] *= 2;
                    }
                    // Recursive call without depth validation
                    processRecursive(data, depth - 1);
                }
            }
        }
    "#;

    let detector = ParameterCheckDetector::new();
    let contract = parse_contract(solidity_code).unwrap();
    let ctx = create_analysis_context(&contract);

    let findings = detector.detect(&ctx);

    // Should detect complex validation issues
    assert!(findings.len() >= 2);
}