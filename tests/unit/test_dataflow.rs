use std::collections::{HashMap, HashSet};
use anyhow::Result;

use dataflow::{
    DataFlowAnalysis, DataFlowDirection, DataFlowResult,
    ReachingDefinitions, LiveVariables, TaintAnalysis,
    DefUseChain, DataFlowState, TransferFunction
};
use ir::{IrFunction, ValueId, BlockId, Instruction, IrValue};
use cfg::ControlFlowGraph;

#[test]
fn test_reaching_definitions_analysis() {
    let solidity_code = r#"
        contract Test {
            function example(uint256 x) public pure returns (uint256) {
                uint256 y = x + 1;  // def1: y
                if (x > 0) {
                    y = x * 2;      // def2: y
                } else {
                    y = x - 1;      // def3: y
                }
                return y;           // use: y (should reach all three definitions)
            }
        }
    "#;

    // This test should fail initially - we haven't implemented the analysis yet
    let ir_function = parse_and_lower_to_ir(solidity_code).unwrap();
    let cfg = ControlFlowGraph::from_ir(&ir_function).unwrap();

    let mut analysis = ReachingDefinitions::new(&cfg);
    let result = analysis.analyze();

    assert!(result.is_ok());
    let dataflow_result = result.unwrap();

    // Check that all definitions of 'y' reach the return statement
    let return_block = cfg.exit_blocks().first().unwrap();
    let reaching_defs = dataflow_result.get_entry_state(*return_block);

    // Should have three definitions reaching this point
    assert_eq!(reaching_defs.definitions.len(), 3);

    // Verify specific definitions
    let y_defs = reaching_defs.get_definitions("y");
    assert_eq!(y_defs.len(), 3);
}

#[test]
fn test_live_variables_analysis() {
    let solidity_code = r#"
        contract Test {
            function example(uint256 a, uint256 b) public pure returns (uint256) {
                uint256 x = a + b;  // x is live until return
                uint256 y = a * 2;  // y is dead - never used
                uint256 z = x + 1;  // z is live until return
                return x + z;
            }
        }
    "#;

    let ir_function = parse_and_lower_to_ir(solidity_code).unwrap();
    let cfg = ControlFlowGraph::from_ir(&ir_function).unwrap();

    let mut analysis = LiveVariables::new(&cfg);
    let result = analysis.analyze();

    assert!(result.is_ok());
    let dataflow_result = result.unwrap();

    // Check liveness at the beginning of the function
    let entry_block = cfg.entry_block();
    let live_vars = dataflow_result.get_exit_state(entry_block);

    // Parameters should be live
    assert!(live_vars.contains("a"));
    assert!(live_vars.contains("b"));

    // Check that 'y' is identified as dead
    let y_def_block = find_block_with_definition(&cfg, "y");
    let live_after_y = dataflow_result.get_exit_state(y_def_block);
    assert!(!live_after_y.contains("y")); // y should be dead
}

#[test]
fn test_taint_analysis_source_to_sink() {
    let solidity_code = r#"
        contract Test {
            function vulnerable(string memory userInput) public {
                bytes32 hash = keccak256(abi.encodePacked(userInput)); // taint source
                uint256 index = uint256(hash) % 100;                   // tainted

                // This should be flagged as dangerous
                assembly {
                    let value := mload(add(index, 0x20))  // taint sink
                }
            }
        }
    "#;

    let ir_function = parse_and_lower_to_ir(solidity_code).unwrap();
    let cfg = ControlFlowGraph::from_ir(&ir_function).unwrap();

    let mut analysis = TaintAnalysis::new(&cfg);
    analysis.add_source("userInput");
    analysis.add_sink("mload");

    let result = analysis.analyze();
    assert!(result.is_ok());

    let taint_result = result.unwrap();

    // Should detect taint flow from userInput to mload
    let violations = taint_result.get_violations();
    assert!(!violations.is_empty());

    // Verify the specific taint path
    let violation = &violations[0];
    assert_eq!(violation.source_variable, "userInput");
    assert_eq!(violation.sink_instruction, "mload");
    assert!(violation.taint_path.len() > 1);
}

#[test]
fn test_taint_analysis_sanitization() {
    let solidity_code = r#"
        contract Test {
            function safe(string memory userInput) public pure returns (uint256) {
                require(bytes(userInput).length < 100, "Input too long"); // sanitizer
                bytes32 hash = keccak256(abi.encodePacked(userInput));
                return uint256(hash) % 1000; // should not be tainted after sanitization
            }
        }
    "#;

    let ir_function = parse_and_lower_to_ir(solidity_code).unwrap();
    let cfg = ControlFlowGraph::from_ir(&ir_function).unwrap();

    let mut analysis = TaintAnalysis::new(&cfg);
    analysis.add_source("userInput");
    analysis.add_sanitizer("require");

    let result = analysis.analyze();
    assert!(result.is_ok());

    let taint_result = result.unwrap();

    // After sanitization, the return value should not be tainted
    let return_block = cfg.exit_blocks().first().unwrap();
    let taint_state = taint_result.get_exit_state(*return_block);

    // The hash variable should not be tainted after require
    assert!(!taint_state.is_tainted("hash"));
}

#[test]
fn test_def_use_chains() {
    let solidity_code = r#"
        contract Test {
            function example(uint256 x) public pure returns (uint256) {
                uint256 y = x + 1;    // def1 of y
                uint256 z = y * 2;    // use1 of y, def1 of z
                y = z + x;            // def2 of y, use1 of z
                return y + z;         // use2 of y, use2 of z
            }
        }
    "#;

    let ir_function = parse_and_lower_to_ir(solidity_code).unwrap();
    let cfg = ControlFlowGraph::from_ir(&ir_function).unwrap();

    let def_use_chain = DefUseChain::build(&cfg);

    // Check def-use chains for variable 'y'
    let y_chains = def_use_chain.get_chains("y");
    assert_eq!(y_chains.len(), 2); // Two definitions of y

    // First definition should have one use
    let def1_uses = &y_chains[0].uses;
    assert_eq!(def1_uses.len(), 1);

    // Second definition should have one use
    let def2_uses = &y_chains[1].uses;
    assert_eq!(def2_uses.len(), 1);

    // Check def-use chains for variable 'z'
    let z_chains = def_use_chain.get_chains("z");
    assert_eq!(z_chains.len(), 1); // One definition of z

    let z_uses = &z_chains[0].uses;
    assert_eq!(z_uses.len(), 2); // Two uses of z
}

#[test]
fn test_dataflow_convergence() {
    let solidity_code = r#"
        contract Test {
            function loop_example(uint256 n) public pure returns (uint256) {
                uint256 sum = 0;
                for (uint256 i = 0; i < n; i++) {
                    sum += i;
                }
                return sum;
            }
        }
    "#;

    let ir_function = parse_and_lower_to_ir(solidity_code).unwrap();
    let cfg = ControlFlowGraph::from_ir(&ir_function).unwrap();

    let mut analysis = ReachingDefinitions::new(&cfg);
    let result = analysis.analyze();

    assert!(result.is_ok());
    let dataflow_result = result.unwrap();

    // Analysis should converge even with loops
    assert!(dataflow_result.converged);
    assert!(dataflow_result.iterations > 1);
    assert!(dataflow_result.iterations < 100); // Should converge reasonably quickly
}

#[test]
fn test_complex_control_flow() {
    let solidity_code = r#"
        contract Test {
            function complex(uint256 x, uint256 y) public pure returns (uint256) {
                uint256 result;

                if (x > y) {
                    if (x > 10) {
                        result = x * 2;
                    } else {
                        result = x + y;
                    }
                } else {
                    while (y > 0) {
                        result += y;
                        y--;
                    }
                }

                return result;
            }
        }
    "#;

    let ir_function = parse_and_lower_to_ir(solidity_code).unwrap();
    let cfg = ControlFlowGraph::from_ir(&ir_function).unwrap();

    // Test multiple analyses on complex control flow
    let mut reaching_defs = ReachingDefinitions::new(&cfg);
    let rd_result = reaching_defs.analyze();
    assert!(rd_result.is_ok());

    let mut live_vars = LiveVariables::new(&cfg);
    let lv_result = live_vars.analyze();
    assert!(lv_result.is_ok());

    // Both analyses should handle complex control flow
    let rd_data = rd_result.unwrap();
    let lv_data = lv_result.unwrap();

    assert!(rd_data.converged);
    assert!(lv_data.converged);
}

#[test]
fn test_interprocedural_analysis() {
    let solidity_code = r#"
        contract Test {
            function helper(uint256 x) internal pure returns (uint256) {
                return x * 2;
            }

            function main(uint256 input) public pure returns (uint256) {
                uint256 temp = helper(input);  // function call
                return temp + 1;
            }
        }
    "#;

    let ir_functions = parse_and_lower_multiple_functions(solidity_code).unwrap();

    // For now, test that we can at least analyze each function independently
    for ir_function in ir_functions {
        let cfg = ControlFlowGraph::from_ir(&ir_function).unwrap();

        let mut analysis = ReachingDefinitions::new(&cfg);
        let result = analysis.analyze();
        assert!(result.is_ok());
    }

    // TODO: Implement true interprocedural analysis in future phases
}

#[test]
fn test_dataflow_with_phi_nodes() {
    let solidity_code = r#"
        contract Test {
            function phi_example(uint256 x, bool condition) public pure returns (uint256) {
                uint256 y;
                if (condition) {
                    y = x + 1;
                } else {
                    y = x - 1;
                }
                // At this point, y should have a phi node in SSA form
                return y * 2;
            }
        }
    "#;

    let ir_function = parse_and_lower_to_ir(solidity_code).unwrap();
    let cfg = ControlFlowGraph::from_ir(&ir_function).unwrap();

    let mut analysis = ReachingDefinitions::new(&cfg);
    let result = analysis.analyze();

    assert!(result.is_ok());
    let dataflow_result = result.unwrap();

    // Find the block with the phi node
    let phi_block = find_block_with_phi_node(&cfg, "y");
    let reaching_defs = dataflow_result.get_entry_state(phi_block);

    // Should have two definitions reaching the phi node
    let y_defs = reaching_defs.get_definitions("y");
    assert_eq!(y_defs.len(), 2);
}

// Helper functions that should be implemented alongside the main dataflow code

fn parse_and_lower_to_ir(solidity_code: &str) -> Result<IrFunction> {
    // This should use the parser and lowering infrastructure from Phase 2.1
    // For now, this is a placeholder that will fail until implemented
    unimplemented!("IR lowering not yet connected to tests")
}

fn parse_and_lower_multiple_functions(solidity_code: &str) -> Result<Vec<IrFunction>> {
    // This should parse multiple functions and lower each to IR
    unimplemented!("Multiple function lowering not yet implemented")
}

fn find_block_with_definition(cfg: &ControlFlowGraph, var_name: &str) -> BlockId {
    // Find the basic block containing a definition of the given variable
    unimplemented!("Block analysis helper not yet implemented")
}

fn find_block_with_phi_node(cfg: &ControlFlowGraph, var_name: &str) -> BlockId {
    // Find the basic block containing a phi node for the given variable
    unimplemented!("Phi node analysis helper not yet implemented")
}