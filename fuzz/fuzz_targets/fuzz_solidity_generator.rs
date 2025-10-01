// fuzz/fuzz_targets/fuzz_solidity_generator.rs
// Fuzzing target for Solidity code generation utilities

#![no_main]

use libfuzzer-sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::panic;

/// Fuzzable Solidity generation parameters
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzGenerationParams {
    pub contract_count: u8,
    pub max_functions_per_contract: u8,
    pub max_params_per_function: u8,
    pub include_inheritance: bool,
    pub include_events: bool,
    pub include_modifiers: bool,
    pub solidity_version: FuzzSolidityVersion,
    pub complexity_level: FuzzComplexityLevel,
}

#[derive(Debug, Clone, Arbitrary)]
pub enum FuzzSolidityVersion {
    V0_4,
    V0_5,
    V0_6,
    V0_7,
    V0_8,
}

#[derive(Debug, Clone, Arbitrary)]
pub enum FuzzComplexityLevel {
    Minimal,
    Simple,
    Moderate,
    Complex,
    Maximum,
}

/// Generated contract structure
#[derive(Debug, Clone)]
pub struct GeneratedContract {
    pub name: String,
    pub source: String,
    pub vulnerabilities: Vec<String>,
    pub complexity_score: u32,
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let _ = panic::catch_unwind(|| {
        if let Ok(mut unstructured) = Unstructured::new(data) {
            if let Ok(params) = FuzzGenerationParams::arbitrary(&mut unstructured) {
                fuzz_solidity_generation(&params);
            }
        }
    });
});

fn fuzz_solidity_generation(params: &FuzzGenerationParams) {
    // Generate contracts based on parameters
    for i in 0..params.contract_count.min(10) {
        let contract = generate_contract(i, params);
        validate_generated_contract(&contract);
    }
}

fn generate_contract(index: u8, params: &FuzzGenerationParams) -> GeneratedContract {
    let contract_name = format!("FuzzedContract{}", index);
    let mut source = String::new();

    // Add pragma
    source.push_str(&format!("pragma solidity {};\n\n", get_version_string(&params.solidity_version)));

    // Add imports based on complexity
    if matches!(params.complexity_level, FuzzComplexityLevel::Complex | FuzzComplexityLevel::Maximum) {
        source.push_str("import \"./SafeMath.sol\";\n");
        source.push_str("import \"./Ownable.sol\";\n\n");
    }

    // Start contract
    source.push_str(&format!("contract {} ", contract_name));

    // Add inheritance
    if params.include_inheritance {
        match params.complexity_level {
            FuzzComplexityLevel::Simple => source.push_str("is Ownable "),
            FuzzComplexityLevel::Moderate => source.push_str("is Ownable, ReentrancyGuard "),
            FuzzComplexityLevel::Complex | FuzzComplexityLevel::Maximum => {
                source.push_str("is Ownable, ReentrancyGuard, Pausable ");
            },
            _ => {}
        }
    }

    source.push_str("{\n");

    // Add state variables based on complexity
    add_state_variables(&mut source, params);

    // Add events
    if params.include_events {
        add_events(&mut source, params);
    }

    // Add modifiers
    if params.include_modifiers {
        add_modifiers(&mut source, params);
    }

    // Add constructor
    add_constructor(&mut source, params);

    // Add functions
    add_functions(&mut source, params);

    // Close contract
    source.push_str("}\n");

    // Identify potential vulnerabilities
    let vulnerabilities = identify_vulnerabilities(&source);
    let complexity_score = calculate_complexity(&source);

    GeneratedContract {
        name: contract_name,
        source,
        vulnerabilities,
        complexity_score,
    }
}

fn get_version_string(version: &FuzzSolidityVersion) -> &'static str {
    match version {
        FuzzSolidityVersion::V0_4 => "^0.4.24",
        FuzzSolidityVersion::V0_5 => "^0.5.17",
        FuzzSolidityVersion::V0_6 => "^0.6.12",
        FuzzSolidityVersion::V0_7 => "^0.7.6",
        FuzzSolidityVersion::V0_8 => "^0.8.19",
    }
}

fn add_state_variables(source: &mut String, params: &FuzzGenerationParams) {
    match params.complexity_level {
        FuzzComplexityLevel::Minimal => {
            source.push_str("    uint256 public value;\n");
        },
        FuzzComplexityLevel::Simple => {
            source.push_str("    address public owner;\n");
            source.push_str("    uint256 public balance;\n");
            source.push_str("    bool public active;\n");
        },
        FuzzComplexityLevel::Moderate => {
            source.push_str("    address public owner;\n");
            source.push_str("    mapping(address => uint256) public balances;\n");
            source.push_str("    uint256 public totalSupply;\n");
            source.push_str("    bool public paused;\n");
        },
        FuzzComplexityLevel::Complex => {
            source.push_str("    address public owner;\n");
            source.push_str("    mapping(address => uint256) public balances;\n");
            source.push_str("    mapping(address => mapping(address => uint256)) public allowances;\n");
            source.push_str("    uint256 public totalSupply;\n");
            source.push_str("    string public name;\n");
            source.push_str("    string public symbol;\n");
            source.push_str("    uint8 public decimals;\n");
            source.push_str("    bool public paused;\n");
        },
        FuzzComplexityLevel::Maximum => {
            source.push_str("    address public owner;\n");
            source.push_str("    mapping(address => uint256) public balances;\n");
            source.push_str("    mapping(address => mapping(address => uint256)) public allowances;\n");
            source.push_str("    mapping(address => bool) public whitelist;\n");
            source.push_str("    mapping(bytes32 => bool) public usedNonces;\n");
            source.push_str("    uint256 public totalSupply;\n");
            source.push_str("    uint256 public maxSupply;\n");
            source.push_str("    string public name;\n");
            source.push_str("    string public symbol;\n");
            source.push_str("    uint8 public decimals;\n");
            source.push_str("    bool public paused;\n");
            source.push_str("    uint256 public lastUpdate;\n");
            source.push_str("    address[] public stakeholders;\n");
        },
    }
    source.push_str("\n");
}

fn add_events(source: &mut String, params: &FuzzGenerationParams) {
    match params.complexity_level {
        FuzzComplexityLevel::Minimal => {},
        FuzzComplexityLevel::Simple => {
            source.push_str("    event ValueChanged(uint256 newValue);\n");
        },
        FuzzComplexityLevel::Moderate => {
            source.push_str("    event Transfer(address indexed from, address indexed to, uint256 value);\n");
            source.push_str("    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);\n");
        },
        FuzzComplexityLevel::Complex | FuzzComplexityLevel::Maximum => {
            source.push_str("    event Transfer(address indexed from, address indexed to, uint256 value);\n");
            source.push_str("    event Approval(address indexed owner, address indexed spender, uint256 value);\n");
            source.push_str("    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);\n");
            source.push_str("    event Paused(address account);\n");
            source.push_str("    event Unpaused(address account);\n");
            if matches!(params.complexity_level, FuzzComplexityLevel::Maximum) {
                source.push_str("    event WhitelistUpdated(address indexed account, bool status);\n");
                source.push_str("    event EmergencyWithdraw(address indexed to, uint256 amount);\n");
            }
        },
    }
    source.push_str("\n");
}

fn add_modifiers(source: &mut String, params: &FuzzGenerationParams) {
    if matches!(params.complexity_level, FuzzComplexityLevel::Minimal) {
        return;
    }

    source.push_str("    modifier onlyOwner() {\n");
    source.push_str("        require(msg.sender == owner, \"Not the owner\");\n");
    source.push_str("        _;\n");
    source.push_str("    }\n\n");

    if matches!(params.complexity_level, FuzzComplexityLevel::Moderate | FuzzComplexityLevel::Complex | FuzzComplexityLevel::Maximum) {
        source.push_str("    modifier whenNotPaused() {\n");
        source.push_str("        require(!paused, \"Contract is paused\");\n");
        source.push_str("        _;\n");
        source.push_str("    }\n\n");
    }

    if matches!(params.complexity_level, FuzzComplexityLevel::Maximum) {
        source.push_str("    modifier onlyWhitelisted() {\n");
        source.push_str("        require(whitelist[msg.sender], \"Not whitelisted\");\n");
        source.push_str("        _;\n");
        source.push_str("    }\n\n");

        source.push_str("    modifier validAddress(address _addr) {\n");
        source.push_str("        require(_addr != address(0), \"Invalid address\");\n");
        source.push_str("        _;\n");
        source.push_str("    }\n\n");
    }
}

fn add_constructor(source: &mut String, params: &FuzzGenerationParams) {
    match params.complexity_level {
        FuzzComplexityLevel::Minimal => {
            source.push_str("    constructor() {\n");
            source.push_str("        value = 0;\n");
            source.push_str("    }\n\n");
        },
        FuzzComplexityLevel::Simple => {
            source.push_str("    constructor() {\n");
            source.push_str("        owner = msg.sender;\n");
            source.push_str("        balance = 0;\n");
            source.push_str("        active = true;\n");
            source.push_str("    }\n\n");
        },
        FuzzComplexityLevel::Moderate => {
            source.push_str("    constructor(uint256 _totalSupply) {\n");
            source.push_str("        owner = msg.sender;\n");
            source.push_str("        totalSupply = _totalSupply;\n");
            source.push_str("        balances[owner] = _totalSupply;\n");
            source.push_str("        paused = false;\n");
            source.push_str("    }\n\n");
        },
        FuzzComplexityLevel::Complex => {
            source.push_str("    constructor(string memory _name, string memory _symbol, uint8 _decimals, uint256 _totalSupply) {\n");
            source.push_str("        owner = msg.sender;\n");
            source.push_str("        name = _name;\n");
            source.push_str("        symbol = _symbol;\n");
            source.push_str("        decimals = _decimals;\n");
            source.push_str("        totalSupply = _totalSupply;\n");
            source.push_str("        balances[owner] = _totalSupply;\n");
            source.push_str("        paused = false;\n");
            source.push_str("    }\n\n");
        },
        FuzzComplexityLevel::Maximum => {
            source.push_str("    constructor(\n");
            source.push_str("        string memory _name,\n");
            source.push_str("        string memory _symbol,\n");
            source.push_str("        uint8 _decimals,\n");
            source.push_str("        uint256 _totalSupply,\n");
            source.push_str("        uint256 _maxSupply\n");
            source.push_str("    ) {\n");
            source.push_str("        owner = msg.sender;\n");
            source.push_str("        name = _name;\n");
            source.push_str("        symbol = _symbol;\n");
            source.push_str("        decimals = _decimals;\n");
            source.push_str("        totalSupply = _totalSupply;\n");
            source.push_str("        maxSupply = _maxSupply;\n");
            source.push_str("        balances[owner] = _totalSupply;\n");
            source.push_str("        whitelist[owner] = true;\n");
            source.push_str("        paused = false;\n");
            source.push_str("        lastUpdate = block.timestamp;\n");
            source.push_str("    }\n\n");
        },
    }
}

fn add_functions(source: &mut String, params: &FuzzGenerationParams) {
    let function_count = params.max_functions_per_contract.min(20);

    for i in 0..function_count {
        match params.complexity_level {
            FuzzComplexityLevel::Minimal => {
                add_minimal_function(source, i);
            },
            FuzzComplexityLevel::Simple => {
                add_simple_function(source, i);
            },
            FuzzComplexityLevel::Moderate => {
                add_moderate_function(source, i, params);
            },
            FuzzComplexityLevel::Complex => {
                add_complex_function(source, i, params);
            },
            FuzzComplexityLevel::Maximum => {
                add_maximum_function(source, i, params);
            },
        }
    }
}

fn add_minimal_function(source: &mut String, index: u8) {
    match index {
        0 => {
            source.push_str("    function setValue(uint256 _value) public {\n");
            source.push_str("        value = _value;\n");
            source.push_str("    }\n\n");
        },
        1 => {
            source.push_str("    function getValue() public view returns (uint256) {\n");
            source.push_str("        return value;\n");
            source.push_str("    }\n\n");
        },
        _ => {}
    }
}

fn add_simple_function(source: &mut String, index: u8) {
    match index {
        0 => {
            source.push_str("    function deposit() public payable {\n");
            source.push_str("        balance += msg.value;\n");
            source.push_str("    }\n\n");
        },
        1 => {
            // Potentially vulnerable function - missing access control
            source.push_str("    function withdraw(uint256 amount) public {\n");
            source.push_str("        require(amount <= balance, \"Insufficient balance\");\n");
            source.push_str("        balance -= amount;\n");
            source.push_str("        payable(msg.sender).transfer(amount);\n");
            source.push_str("    }\n\n");
        },
        2 => {
            source.push_str("    function transferOwnership(address newOwner) public onlyOwner {\n");
            source.push_str("        require(newOwner != address(0), \"Invalid address\");\n");
            source.push_str("        owner = newOwner;\n");
            source.push_str("    }\n\n");
        },
        _ => {}
    }
}

fn add_moderate_function(source: &mut String, index: u8, params: &FuzzGenerationParams) {
    match index {
        0 => {
            source.push_str("    function transfer(address to, uint256 amount) public whenNotPaused returns (bool) {\n");
            source.push_str("        require(to != address(0), \"Transfer to zero address\");\n");
            source.push_str("        require(balances[msg.sender] >= amount, \"Insufficient balance\");\n");
            source.push_str("        balances[msg.sender] -= amount;\n");
            source.push_str("        balances[to] += amount;\n");
            if params.include_events {
                source.push_str("        emit Transfer(msg.sender, to, amount);\n");
            }
            source.push_str("        return true;\n");
            source.push_str("    }\n\n");
        },
        1 => {
            // Potentially vulnerable - reentrancy risk
            source.push_str("    function withdraw(uint256 amount) public {\n");
            source.push_str("        require(balances[msg.sender] >= amount, \"Insufficient balance\");\n");
            source.push_str("        (bool success, ) = msg.sender.call{value: amount}(\"\");\n");
            source.push_str("        require(success, \"Transfer failed\");\n");
            source.push_str("        balances[msg.sender] -= amount;\n");
            source.push_str("    }\n\n");
        },
        2 => {
            source.push_str("    function pause() public onlyOwner {\n");
            source.push_str("        paused = true;\n");
            if params.include_events {
                source.push_str("        emit Paused(msg.sender);\n");
            }
            source.push_str("    }\n\n");
        },
        3 => {
            source.push_str("    function unpause() public onlyOwner {\n");
            source.push_str("        paused = false;\n");
            if params.include_events {
                source.push_str("        emit Unpaused(msg.sender);\n");
            }
            source.push_str("    }\n\n");
        },
        _ => {}
    }
}

fn add_complex_function(source: &mut String, index: u8, params: &FuzzGenerationParams) {
    match index {
        0 => {
            source.push_str("    function approve(address spender, uint256 amount) public returns (bool) {\n");
            source.push_str("        require(spender != address(0), \"Approve to zero address\");\n");
            source.push_str("        allowances[msg.sender][spender] = amount;\n");
            if params.include_events {
                source.push_str("        emit Approval(msg.sender, spender, amount);\n");
            }
            source.push_str("        return true;\n");
            source.push_str("    }\n\n");
        },
        1 => {
            source.push_str("    function transferFrom(address from, address to, uint256 amount) public returns (bool) {\n");
            source.push_str("        require(from != address(0), \"Transfer from zero address\");\n");
            source.push_str("        require(to != address(0), \"Transfer to zero address\");\n");
            source.push_str("        require(balances[from] >= amount, \"Insufficient balance\");\n");
            source.push_str("        require(allowances[from][msg.sender] >= amount, \"Insufficient allowance\");\n");
            source.push_str("        balances[from] -= amount;\n");
            source.push_str("        balances[to] += amount;\n");
            source.push_str("        allowances[from][msg.sender] -= amount;\n");
            if params.include_events {
                source.push_str("        emit Transfer(from, to, amount);\n");
            }
            source.push_str("        return true;\n");
            source.push_str("    }\n\n");
        },
        2 => {
            // Potentially vulnerable - timestamp dependence
            source.push_str("    function timeBasedFunction() public view returns (bool) {\n");
            source.push_str("        return block.timestamp % 2 == 0;\n");
            source.push_str("    }\n\n");
        },
        3 => {
            // Potentially vulnerable - tx.origin usage
            source.push_str("    function authenticate() public view returns (bool) {\n");
            source.push_str("        return tx.origin == owner;\n");
            source.push_str("    }\n\n");
        },
        _ => {}
    }
}

fn add_maximum_function(source: &mut String, index: u8, params: &FuzzGenerationParams) {
    match index {
        0 => {
            source.push_str("    function mint(address to, uint256 amount) public onlyOwner validAddress(to) {\n");
            source.push_str("        require(totalSupply + amount <= maxSupply, \"Exceeds max supply\");\n");
            source.push_str("        balances[to] += amount;\n");
            source.push_str("        totalSupply += amount;\n");
            source.push_str("        lastUpdate = block.timestamp;\n");
            if params.include_events {
                source.push_str("        emit Transfer(address(0), to, amount);\n");
            }
            source.push_str("    }\n\n");
        },
        1 => {
            source.push_str("    function updateWhitelist(address account, bool status) public onlyOwner {\n");
            source.push_str("        whitelist[account] = status;\n");
            if params.include_events {
                source.push_str("        emit WhitelistUpdated(account, status);\n");
            }
            source.push_str("    }\n\n");
        },
        2 => {
            // Complex function with multiple vulnerabilities
            source.push_str("    function complexTransfer(\n");
            source.push_str("        address to,\n");
            source.push_str("        uint256 amount,\n");
            source.push_str("        bytes32 nonce,\n");
            source.push_str("        bytes memory signature\n");
            source.push_str("    ) public onlyWhitelisted {\n");
            source.push_str("        require(!usedNonces[nonce], \"Nonce already used\");\n");
            source.push_str("        require(balances[msg.sender] >= amount, \"Insufficient balance\");\n");
            source.push_str("        \n");
            source.push_str("        // Vulnerable: external call before state update\n");
            source.push_str("        (bool success, ) = to.call{value: amount}(\"\");\n");
            source.push_str("        require(success, \"Transfer failed\");\n");
            source.push_str("        \n");
            source.push_str("        balances[msg.sender] -= amount;\n");
            source.push_str("        usedNonces[nonce] = true;\n");
            source.push_str("        lastUpdate = block.timestamp;\n");
            source.push_str("    }\n\n");
        },
        3 => {
            // Dangerous delegatecall
            source.push_str("    function proxyCall(address target, bytes memory data) public onlyOwner {\n");
            source.push_str("        (bool success, ) = target.delegatecall(data);\n");
            source.push_str("        require(success, \"Delegatecall failed\");\n");
            source.push_str("    }\n\n");
        },
        4 => {
            // Emergency function with selfdestruct
            source.push_str("    function emergencyDestroy() public onlyOwner {\n");
            source.push_str("        selfdestruct(payable(owner));\n");
            source.push_str("    }\n\n");
        },
        _ => {}
    }
}

fn identify_vulnerabilities(source: &str) -> Vec<String> {
    let mut vulnerabilities = Vec::new();

    // Check for various vulnerability patterns
    if source.contains("call{value:") && source.contains("balances[msg.sender] -=") {
        let call_pos = source.find("call{value:").unwrap_or(0);
        let balance_pos = source.find("balances[msg.sender] -=").unwrap_or(0);
        if call_pos < balance_pos {
            vulnerabilities.push("reentrancy".to_string());
        }
    }

    if source.contains("tx.origin") {
        vulnerabilities.push("tx-origin".to_string());
    }

    if source.contains("block.timestamp") {
        vulnerabilities.push("timestamp-dependence".to_string());
    }

    if source.contains("delegatecall") {
        vulnerabilities.push("dangerous-delegatecall".to_string());
    }

    if source.contains("selfdestruct") {
        vulnerabilities.push("unprotected-selfdestruct".to_string());
    }

    // Check for missing access control
    if source.contains("function withdraw") && !source.contains("onlyOwner") {
        vulnerabilities.push("missing-access-control".to_string());
    }

    vulnerabilities
}

fn calculate_complexity(source: &str) -> u32 {
    let mut score = 0u32;

    // Basic complexity metrics
    score += source.matches("function").count() as u32 * 10;
    score += source.matches("modifier").count() as u32 * 15;
    score += source.matches("if").count() as u32 * 5;
    score += source.matches("for").count() as u32 * 10;
    score += source.matches("while").count() as u32 * 10;
    score += source.matches("require").count() as u32 * 3;
    score += source.matches("mapping").count() as u32 * 8;
    score += source.matches("event").count() as u32 * 5;

    // Advanced complexity indicators
    score += source.matches("delegatecall").count() as u32 * 20;
    score += source.matches("assembly").count() as u32 * 30;
    score += source.matches("selfdestruct").count() as u32 * 25;

    score
}

fn validate_generated_contract(contract: &GeneratedContract) {
    // Basic validation
    assert!(!contract.name.is_empty(), "Contract name cannot be empty");
    assert!(!contract.source.is_empty(), "Contract source cannot be empty");
    assert!(contract.source.contains("pragma solidity"), "Must have pragma directive");
    assert!(contract.source.contains("contract "), "Must have contract declaration");

    // Structure validation
    let open_braces = contract.source.matches('{').count();
    let close_braces = contract.source.matches('}').count();
    assert_eq!(open_braces, close_braces, "Unmatched braces in generated contract");

    // Complexity validation
    assert!(contract.complexity_score < 10000, "Complexity score too high: {}", contract.complexity_score);

    // Vulnerability validation
    for vuln in &contract.vulnerabilities {
        assert!(!vuln.is_empty(), "Vulnerability name cannot be empty");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_generation() {
        let params = FuzzGenerationParams {
            contract_count: 3,
            max_functions_per_contract: 5,
            max_params_per_function: 3,
            include_inheritance: true,
            include_events: true,
            include_modifiers: true,
            solidity_version: FuzzSolidityVersion::V0_8,
            complexity_level: FuzzComplexityLevel::Moderate,
        };

        for i in 0..params.contract_count {
            let contract = generate_contract(i, &params);
            validate_generated_contract(&contract);
        }
    }

    #[test]
    fn test_vulnerability_identification() {
        let vulnerable_source = r#"
        pragma solidity ^0.8.0;
        contract VulnerableContract {
            mapping(address => uint256) balances;

            function withdraw() public {
                uint256 amount = balances[msg.sender];
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success);
                balances[msg.sender] -= amount;
            }

            function authenticate() public view returns (bool) {
                return tx.origin == msg.sender;
            }
        }
        "#;

        let vulnerabilities = identify_vulnerabilities(vulnerable_source);
        assert!(vulnerabilities.contains(&"reentrancy".to_string()));
        assert!(vulnerabilities.contains(&"tx-origin".to_string()));
    }

    #[test]
    fn test_complexity_calculation() {
        let simple_source = r#"
        pragma solidity ^0.8.0;
        contract Simple {
            uint256 value;
            function setValue(uint256 _value) public {
                value = _value;
            }
        }
        "#;

        let complex_source = r#"
        pragma solidity ^0.8.0;
        contract Complex {
            mapping(address => uint256) balances;
            modifier onlyOwner() { _; }
            event Transfer(address from, address to, uint256 value);

            function complexFunction(address to, uint256 amount) public onlyOwner {
                require(amount > 0);
                if (balances[msg.sender] >= amount) {
                    for (uint i = 0; i < 10; i++) {
                        balances[to] += 1;
                    }
                }
                emit Transfer(msg.sender, to, amount);
            }
        }
        "#;

        let simple_complexity = calculate_complexity(simple_source);
        let complex_complexity = calculate_complexity(complex_source);

        assert!(complex_complexity > simple_complexity);
    }

    #[test]
    fn test_version_strings() {
        assert_eq!(get_version_string(&FuzzSolidityVersion::V0_4), "^0.4.24");
        assert_eq!(get_version_string(&FuzzSolidityVersion::V0_8), "^0.8.19");
    }

    #[test]
    fn test_all_complexity_levels() {
        let complexity_levels = [
            FuzzComplexityLevel::Minimal,
            FuzzComplexityLevel::Simple,
            FuzzComplexityLevel::Moderate,
            FuzzComplexityLevel::Complex,
            FuzzComplexityLevel::Maximum,
        ];

        for level in &complexity_levels {
            let params = FuzzGenerationParams {
                contract_count: 1,
                max_functions_per_contract: 3,
                max_params_per_function: 2,
                include_inheritance: true,
                include_events: true,
                include_modifiers: true,
                solidity_version: FuzzSolidityVersion::V0_8,
                complexity_level: level.clone(),
            };

            let contract = generate_contract(0, &params);
            validate_generated_contract(&contract);

            // Verify that complexity increases with level
            match level {
                FuzzComplexityLevel::Minimal => {
                    assert!(contract.complexity_score < 100);
                },
                FuzzComplexityLevel::Maximum => {
                    assert!(contract.complexity_score > 200);
                },
                _ => {}
            }
        }
    }
}