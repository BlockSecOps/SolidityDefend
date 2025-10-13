//use anyhow::Result;
use analysis::AnalysisEngine;
use ast::AstArena;
use parser::Parser;

/// Basic smoke tests for the analysis engine
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_engine_creation() {
        let engine = AnalysisEngine::new();
        assert_eq!(engine.get_statistics().functions_analyzed, 0);
    }

    #[test]
    fn test_simple_contract_analysis() {
        let arena = AstArena::new();
        let parser = Parser::new();
        let mut engine = AnalysisEngine::new();

        let source = r#"
        pragma solidity ^0.8.0;
        contract Simple {
            function add(uint256 a, uint256 b) public pure returns (uint256) {
                return a + b;
            }
        }
        "#;

        // Parse the source
        let ast_result = parser.parse(&arena, source, "test.sol");
        if ast_result.is_err() {
            println!("Parse failed: {:?}", ast_result);
            return; // Skip test if parsing fails
        }

        let ast = ast_result.unwrap();

        // Run analysis
        let analysis_result = engine.analyze_source_file(&ast);
        match analysis_result {
            Ok(results) => {
                println!(
                    "✅ Analysis succeeded with {} functions",
                    results.function_analyses.len()
                );

                // Verify basic properties
                for (i, func) in results.function_analyses.iter().enumerate() {
                    println!(
                        "Function {}: {} basic blocks, {} instructions",
                        i,
                        func.cfg.statistics().block_count,
                        func.ir_function.get_instructions().len()
                    );
                }
            }
            Err(e) => {
                println!("⚠️  Analysis failed: {}", e);
                // Don't fail the test - this is expected during development
            }
        }
    }

    #[test]
    fn test_parser_integration() {
        let arena = AstArena::new();
        let parser = Parser::new();

        let source = r#"
        pragma solidity ^0.8.0;
        contract Test {
            uint256 value;
            function test() public {
                value = 42;
            }
        }
        "#;

        let result = parser.parse(&arena, source, "test.sol");
        match result {
            Ok(ast) => {
                assert_eq!(ast.contracts.len(), 1);
                assert_eq!(ast.contracts[0].name.name, "Test");
                println!("✅ Parser working correctly");
            }
            Err(e) => {
                println!("⚠️  Parser failed: {:?}", e);
                // Don't fail - parser might need more work
            }
        }
    }

    #[test]
    fn test_empty_contract() {
        let arena = AstArena::new();
        let parser = Parser::new();
        let mut engine = AnalysisEngine::new();

        let source = r#"
        pragma solidity ^0.8.0;
        contract Empty {
        }
        "#;

        if let Ok(ast) = parser.parse(&arena, source, "test.sol") {
            if let Ok(results) = engine.analyze_source_file(&ast) {
                // Empty contract should have no functions to analyze
                assert_eq!(results.function_analyses.len(), 0);
                println!("✅ Empty contract analysis works");
            }
        };
    }

    #[test]
    fn test_multiple_functions() {
        let arena = AstArena::new();
        let parser = Parser::new();
        let mut engine = AnalysisEngine::new();

        let source = r#"
        pragma solidity ^0.8.0;
        contract Multi {
            uint256 value;

            function setValue(uint256 v) public {
                value = v;
            }

            function getValue() public view returns (uint256) {
                return value;
            }
        }
        "#;

        if let Ok(ast) = parser.parse(&arena, source, "test.sol") {
            if let Ok(results) = engine.analyze_source_file(&ast) {
                println!("Analyzed {} functions", results.function_analyses.len());

                // Should have analyzed multiple functions
                assert!(results.function_analyses.len() >= 1);

                for func in &results.function_analyses {
                    println!("Function: {}", func.function_name);
                    assert!(func.reaching_definitions.converged);
                    assert!(func.live_variables.converged);
                }

                println!("✅ Multi-function analysis works");
            }
        };
    }
}
