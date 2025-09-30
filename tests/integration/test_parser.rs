use parser::Parser;
use ast::AstArena;

/// Integration tests for the Solidity parser
/// These tests verify the parser implementation works correctly

#[test]
fn test_parse_simple_contract() {
    let source = r#"
        pragma solidity ^0.8.0;

        contract SimpleToken {
            string public name = "Test Token";
            uint256 public totalSupply;

            constructor(uint256 _totalSupply) {
                totalSupply = _totalSupply;
            }

            function transfer(address to, uint256 amount) public returns (bool) {
                return true;
            }
        }
    "#;

    let arena = AstArena::new();
    let parser = Parser::new();
    let result = parser.parse(&arena, source, "SimpleToken.sol");

    assert!(result.is_ok(), "Parser should handle simple contract: {:?}", result);

    let source_file = result.unwrap();
    assert_eq!(source_file.contracts.len(), 1);
    let contract = &source_file.contracts[0];
    assert_eq!(contract.name.name, "SimpleToken");
    // Note: We only have basic function parsing, not full state variable parsing yet
    assert!(contract.functions.len() >= 1); // At least constructor or transfer function
}

#[test]
fn test_parse_contract_with_inheritance() {
    let source = r#"
        pragma solidity ^0.8.0;

        contract Base {
            uint256 public baseValue;
        }

        contract Derived is Base {
            uint256 public derivedValue;

            function setValue(uint256 _value) public {
                baseValue = _value;
            }
        }
    "#;

    let arena = AstArena::new();
    let parser = Parser::new();
    let result = parser.parse(&arena, source, "Inheritance.sol");

    assert!(result.is_ok(), "Parser should handle inheritance: {:?}", result);

    let source_file = result.unwrap();
    assert_eq!(source_file.contracts.len(), 2);

    let base_contract = source_file.contracts.iter().find(|c| c.name.name == "Base").unwrap();
    let derived_contract = source_file.contracts.iter().find(|c| c.name.name == "Derived").unwrap();

    assert_eq!(base_contract.name.name, "Base");
    assert_eq!(derived_contract.name.name, "Derived");
}

#[test]
fn test_parse_contract_with_modifiers() {
    let source = r#"
        pragma solidity ^0.8.0;

        contract ModifierExample {
            address public owner;

            modifier onlyOwner() {
                require(msg.sender == owner, "Not owner");
                _;
            }

            function restrictedFunction() public onlyOwner {
                // Function body
            }
        }
    "#;

    let arena = AstArena::new();
    let parser = Parser::new();
    let result = parser.parse(&arena, source, "Modifiers.sol");

    assert!(result.is_ok(), "Parser should handle modifiers: {:?}", result);

    let source_file = result.unwrap();
    assert_eq!(source_file.contracts.len(), 1);
    assert_eq!(source_file.contracts[0].name.name, "ModifierExample");
}

#[test]
fn test_parse_contract_with_events() {
    let source = r#"
        pragma solidity ^0.8.0;

        contract EventExample {
            event Transfer(address indexed from, address indexed to, uint256 value);
            event Approval(address indexed owner, address indexed spender, uint256 value);

            function emitTransfer() public {
                emit Transfer(msg.sender, address(0), 100);
            }
        }
    "#;

    let arena = AstArena::new();
    let parser = Parser::new();
    let result = parser.parse(&arena, source, "Events.sol");

    assert!(result.is_ok(), "Parser should handle events: {:?}", result);

    let source_file = result.unwrap();
    assert_eq!(source_file.contracts.len(), 1);
    assert_eq!(source_file.contracts[0].name.name, "EventExample");
}

#[test]
fn test_parse_multiple_contracts() {
    let source = r#"
        pragma solidity ^0.8.0;

        interface IERC20 {
            function totalSupply() external view returns (uint256);
            function balanceOf(address account) external view returns (uint256);
        }

        library SafeMath {
            function add(uint256 a, uint256 b) internal pure returns (uint256) {
                return a + b;
            }
        }

        contract Token is IERC20 {
            using SafeMath for uint256;

            uint256 private _totalSupply;

            function totalSupply() external view override returns (uint256) {
                return _totalSupply;
            }

            function balanceOf(address account) external view override returns (uint256) {
                return 0;
            }
        }
    "#;

    let arena = AstArena::new();
    let parser = Parser::new();
    let result = parser.parse(&arena, source, "Multiple.sol");

    assert!(result.is_ok(), "Parser should handle multiple contracts: {:?}", result);

    let source_file = result.unwrap();
    assert_eq!(source_file.contracts.len(), 3); // interface, library, contract

    let contract_names: Vec<&str> = source_file.contracts.iter()
        .map(|c| c.name.name)
        .collect();

    assert!(contract_names.contains(&"IERC20"));
    assert!(contract_names.contains(&"SafeMath"));
    assert!(contract_names.contains(&"Token"));
}

#[test]
fn test_parse_file_from_fixture() {
    let arena = AstArena::new();
    let parser = Parser::new();

    // Test parsing one of our fixture files
    let result = parser.parse_file(&arena, "tests/fixtures/ERC20.sol");

    assert!(result.is_ok(), "Parser should handle ERC20 fixture: {:?}", result);

    let source_file = result.unwrap();
    assert!(source_file.contracts.len() >= 1);

    // Should find the ERC20 contract
    let erc20_contract = source_file.contracts.iter()
        .find(|c| c.name.name == "ERC20");
    assert!(erc20_contract.is_some(), "Should find ERC20 contract");
}

#[test]
fn test_parser_performance() {
    use std::time::Instant;

    let arena = AstArena::new();
    let parser = Parser::new();

    // Load a larger contract
    let source = std::fs::read_to_string("tests/fixtures/UniswapV2Pair.sol")
        .expect("Should be able to read UniswapV2Pair.sol");

    let start = Instant::now();
    let result = parser.parse(&arena, &source, "UniswapV2Pair.sol");
    let duration = start.elapsed();

    assert!(result.is_ok(), "Parser should handle UniswapV2Pair: {:?}", result);

    // Should parse in reasonable time (< 100ms for this size)
    assert!(duration.as_millis() < 100, "Parse time should be < 100ms, was: {}ms", duration.as_millis());

    let source_file = result.unwrap();
    assert_eq!(source_file.contracts.len(), 1);
    assert_eq!(source_file.contracts[0].name.name, "UniswapV2Pair");
}

#[test]
fn test_parser_error_handling() {
    let arena = AstArena::new();
    let parser = Parser::new();

    // Test with invalid syntax
    let invalid_source = r#"
        contract InvalidSyntax {
            function test() public {
                // Missing closing brace
        }
    "#;

    let result = parser.parse(&arena, invalid_source, "invalid.sol");
    assert!(result.is_err(), "Parser should reject invalid syntax");

    // Test with non-existent file
    let file_result = parser.parse_file(&arena, "nonexistent.sol");
    assert!(file_result.is_err(), "Parser should handle missing files");
}

#[test]
fn test_syntax_validation() {
    let parser = Parser::new();

    // Valid syntax
    let valid = "contract Test { function test() public {} }";
    assert!(parser.validate_syntax(valid).is_ok());

    // Invalid syntax
    let invalid = "contract Test { function test() public { ";
    assert!(parser.validate_syntax(invalid).is_err());
}