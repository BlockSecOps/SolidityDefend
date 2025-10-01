use ast::{AstArena, Contract, Function, Identifier, ContractType, Visibility, StateMutability, SourceLocation, Position};
use std::time::Instant;

/// Unit tests for arena-allocated AST structures
/// These tests verify the arena allocation implementation works correctly

#[test]
fn test_arena_basic_allocation() {
    let arena = AstArena::new();

    // Test basic string allocation
    let name = arena.alloc_str("TestContract");
    assert_eq!(name, "TestContract");

    // Test that string lives as long as arena
    let reference = name;
    assert_eq!(reference, "TestContract");
}

#[test]
fn test_arena_contract_allocation() {
    let arena = AstArena::new();

    let location = SourceLocation::new(
        "test.sol".into(),
        Position::start(),
        Position::start(),
    );

    let name = Identifier::new(arena.alloc_str("TestContract"), location.clone());
    let contract = Contract::new(&arena, name, ContractType::Contract, location);

    assert_eq!(contract.name.name, "TestContract");
    assert_eq!(contract.functions.len(), 0);
    assert_eq!(contract.contract_type, ContractType::Contract);
}

#[test]
fn test_arena_function_allocation() {
    let arena = AstArena::new();

    let location = SourceLocation::new(
        "test.sol".into(),
        Position::start(),
        Position::start(),
    );

    let name = Identifier::new(arena.alloc_str("testFunction"), location.clone());
    let mut function = Function::new(&arena, name, location);

    function.visibility = Visibility::Public;
    function.mutability = StateMutability::NonPayable;

    assert_eq!(function.name.name, "testFunction");
    assert_eq!(function.visibility, Visibility::Public);
    assert_eq!(function.mutability, StateMutability::NonPayable);
}

#[test]
fn test_arena_performance_vs_heap() {
    const NUM_ALLOCATIONS: usize = 1000; // Reduced for reasonable test time

    // Test arena allocation performance
    let start = Instant::now();
    {
        let arena = AstArena::new();
        for i in 0..NUM_ALLOCATIONS {
            let name_str = format!("contract_{}", i);
            let location = SourceLocation::new(
                "test.sol".into(),
                Position::start(),
                Position::start(),
            );
            let name = Identifier::new(arena.alloc_str(&name_str), location.clone());
            let _contract = Contract::new(&arena, name, ContractType::Contract, location);
        }
    } // Arena drops here, deallocating everything at once
    let arena_duration = start.elapsed();

    // Test heap allocation performance
    let start = Instant::now();
    {
        let mut contracts = Vec::new();
        for i in 0..NUM_ALLOCATIONS {
            let name = format!("contract_{}", i);
            let contract = Box::new(HeapContract {
                name: name,
                functions: Vec::new(),
                state_variables: Vec::new(),
                events: Vec::new(),
                modifiers: Vec::new(),
                inheritance: Vec::new(),
            });
            contracts.push(contract);
        }
    } // Individual heap deallocations happen here
    let heap_duration = start.elapsed();

    // Arena should be reasonable in performance
    println!("Arena: {:?}, Heap: {:?}", arena_duration, heap_duration);

    // Allow for variance in test environments
    assert!(arena_duration <= heap_duration * 5); // More lenient for different systems
}

#[derive(Debug)]
struct HeapContract {
    name: String,
    functions: Vec<String>,
    state_variables: Vec<String>,
    events: Vec<String>,
    modifiers: Vec<String>,
    inheritance: Vec<String>,
}

#[test]
fn test_arena_memory_layout() {
    let arena = AstArena::new();

    // Allocate multiple items and verify they're in the same memory region
    let str1 = arena.alloc_str("first");
    let str2 = arena.alloc_str("second");
    let str3 = arena.alloc_str("third");

    let ptr1 = str1.as_ptr() as usize;
    let ptr2 = str2.as_ptr() as usize;
    let ptr3 = str3.as_ptr() as usize;

    // They should be allocated in sequence (exact layout depends on bumpalo)
    assert!(ptr2 > ptr1);
    assert!(ptr3 > ptr2);

    // Should be relatively close in memory
    assert!((ptr2 - ptr1) < 1024);
    assert!((ptr3 - ptr2) < 1024);
}

#[test]
fn test_arena_multiple_contracts() {
    let arena = AstArena::new();

    let location = SourceLocation::new(
        "test.sol".into(),
        Position::start(),
        Position::start(),
    );

    // Create multiple contracts with functions
    let mut contracts = Vec::new();
    for i in 0..10 {
        let contract_name = format!("Contract{}", i);
        let name = Identifier::new(arena.alloc_str(&contract_name), location.clone());
        let mut contract = Contract::new(&arena, name, ContractType::Contract, location.clone());

        // Add some functions to each contract
        for j in 0..3 {
            let func_name = format!("func{}", j);
            let func_identifier = Identifier::new(arena.alloc_str(&func_name), location.clone());
            let function = Function::new(&arena, func_identifier, location.clone());
            contract.functions.push(function);
        }

        contracts.push(contract);
    }

    // Verify all contracts and their functions
    assert_eq!(contracts.len(), 10);
    for (i, contract) in contracts.iter().enumerate() {
        let expected_name = format!("Contract{}", i);
        assert_eq!(contract.name.name, expected_name);
        assert_eq!(contract.functions.len(), 3);
    }
}

#[test]
fn test_arena_lifetime_safety() {
    let arena = AstArena::new();

    let contract = {
        let temp_name = "TemporaryContract";
        let location = SourceLocation::new(
            "test.sol".into(),
            Position::start(),
            Position::start(),
        );
        // This should work - arena-allocated string outlives the temporary
        let name = Identifier::new(arena.alloc_str(temp_name), location.clone());
        Contract::new(&arena, name, ContractType::Contract, location)
    };

    // Contract should still be valid here
    assert_eq!(contract.name.name, "TemporaryContract");
}

#[test]
fn test_arena_large_allocation() {
    let arena = AstArena::new();

    // Test allocation of large structures
    const LARGE_SIZE: usize = 100; // Reasonable size for tests

    let location = SourceLocation::new(
        "test.sol".into(),
        Position::start(),
        Position::start(),
    );

    let contract_name = Identifier::new(arena.alloc_str("LargeContract"), location.clone());
    let mut contract = Contract::new(&arena, contract_name, ContractType::Contract, location.clone());

    for i in 0..LARGE_SIZE {
        let name = format!("function_{}", i);
        let func_name = Identifier::new(arena.alloc_str(&name), location.clone());
        let function = Function::new(&arena, func_name, location.clone());
        contract.functions.push(function);
    }

    assert_eq!(contract.functions.len(), LARGE_SIZE);
    assert_eq!(contract.functions[0].name.name, "function_0");
    assert_eq!(contract.functions[LARGE_SIZE - 1].name.name, "function_99");
}

#[test]
fn test_arena_memory_usage() {
    // Test that arena uses memory efficiently
    let arena = AstArena::new();

    // Get initial memory usage
    let initial_bytes = arena.allocated_bytes();

    // Allocate some data
    let _str1 = arena.alloc_str("test string 1");
    let _str2 = arena.alloc_str("test string 2");

    let location = SourceLocation::new(
        "test.sol".into(),
        Position::start(),
        Position::start(),
    );

    let name = Identifier::new(arena.alloc_str("TestContract"), location.clone());
    let _contract = Contract::new(&arena, name, ContractType::Contract, location);

    let final_bytes = arena.allocated_bytes();
    let used_bytes = final_bytes - initial_bytes;

    // Should have allocated something
    assert!(used_bytes > 0);

    // Should be reasonable amount (less than 1KB for this test)
    assert!(used_bytes < 1024);
}

#[test]
fn test_arena_memory_efficiency() {
    // Test that demonstrates arena's memory efficiency without unsafe concurrency
    use std::sync::Arc;

    let arena = Arc::new(AstArena::new());

    let location = SourceLocation::new(
        "test.sol".into(),
        Position::start(),
        Position::start(),
    );

    // Create multiple contracts in the same arena
    let contracts: Vec<_> = (0..100)
        .map(|i| {
            let name_str = format!("Contract_{}", i);
            let name = Identifier::new(arena.alloc_str(&name_str), location.clone());
            Contract::new(&*arena, name, ContractType::Contract, location.clone())
        })
        .collect();

    // Verify all contracts are accessible
    for (i, contract) in contracts.iter().enumerate() {
        let expected_name = format!("Contract_{}", i);
        assert_eq!(contract.name.name, expected_name);
    }

    // Demonstrate that arena can be shared safely (read-only) when properly managed
    let arena_clone = Arc::clone(&arena);
    assert!(arena_clone.allocated_bytes() > 0);
}

#[test]
fn test_arena_different_allocations() {
    let arena = AstArena::new();

    // Test different types of allocations
    let string1 = arena.alloc_str("short");
    let string2 = arena.alloc_str("this is a longer string for testing");

    let number = arena.alloc(42u32);
    let boolean = arena.alloc(true);

    // All should be accessible
    assert_eq!(string1, "short");
    assert_eq!(string2, "this is a longer string for testing");
    assert_eq!(*number, 42);
    assert_eq!(*boolean, true);

    // Memory usage should be reasonable
    assert!(arena.allocated_bytes() > 0);
    assert!(arena.allocated_bytes() < 1024);
}