use ast::{Arena, Contract, Function, AstNode};
use bumpalo::Bump;
use std::time::Instant;

/// Unit tests for arena-allocated AST structures
/// These tests must fail initially and pass after implementation

#[test]
fn test_arena_basic_allocation() {
    let arena = Arena::new();

    // Test basic string allocation
    let name = arena.alloc_str("TestContract");
    assert_eq!(name, "TestContract");

    // Test that string lives as long as arena
    let reference = name;
    drop(name);
    assert_eq!(reference, "TestContract");
}

#[test]
fn test_arena_contract_allocation() {
    let arena = Arena::new();

    let contract = arena.alloc(Contract {
        name: arena.alloc_str("TestContract"),
        functions: arena.alloc_slice(&[]),
        state_variables: arena.alloc_slice(&[]),
        events: arena.alloc_slice(&[]),
        modifiers: arena.alloc_slice(&[]),
        inheritance: arena.alloc_slice(&[]),
        location: Default::default(),
        contract_type: ast::ContractType::Contract,
    });

    assert_eq!(contract.name, "TestContract");
    assert_eq!(contract.functions.len(), 0);
}

#[test]
fn test_arena_function_allocation() {
    let arena = Arena::new();

    let function = arena.alloc(Function {
        name: arena.alloc_str("testFunction"),
        visibility: ast::Visibility::Public,
        mutability: ast::StateMutability::NonPayable,
        parameters: arena.alloc_slice(&[]),
        returns: arena.alloc_slice(&[]),
        body: None,
        modifiers: arena.alloc_slice(&[]),
        location: Default::default(),
    });

    assert_eq!(function.name, "testFunction");
    assert_eq!(function.visibility, ast::Visibility::Public);
}

#[test]
fn test_arena_performance_vs_heap() {
    const NUM_ALLOCATIONS: usize = 10000;

    // Test arena allocation performance
    let start = Instant::now();
    {
        let arena = Arena::new();
        for i in 0..NUM_ALLOCATIONS {
            let name = format!("contract_{}", i);
            let _contract = arena.alloc(Contract {
                name: arena.alloc_str(&name),
                functions: arena.alloc_slice(&[]),
                state_variables: arena.alloc_slice(&[]),
                events: arena.alloc_slice(&[]),
                modifiers: arena.alloc_slice(&[]),
                inheritance: arena.alloc_slice(&[]),
                location: Default::default(),
                contract_type: ast::ContractType::Contract,
            });
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

    // Arena should be faster due to batch deallocation
    println!("Arena: {:?}, Heap: {:?}", arena_duration, heap_duration);

    // Allow some variance in test environments
    assert!(arena_duration <= heap_duration * 2);
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
    let arena = Arena::new();

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
fn test_arena_slice_allocation() {
    let arena = Arena::new();

    // Create some functions first
    let func1 = arena.alloc(Function {
        name: arena.alloc_str("func1"),
        visibility: ast::Visibility::Public,
        mutability: ast::StateMutability::Pure,
        parameters: arena.alloc_slice(&[]),
        returns: arena.alloc_slice(&[]),
        body: None,
        modifiers: arena.alloc_slice(&[]),
        location: Default::default(),
    });

    let func2 = arena.alloc(Function {
        name: arena.alloc_str("func2"),
        visibility: ast::Visibility::Internal,
        mutability: ast::StateMutability::View,
        parameters: arena.alloc_slice(&[]),
        returns: arena.alloc_slice(&[]),
        body: None,
        modifiers: arena.alloc_slice(&[]),
        location: Default::default(),
    });

    // Allocate a slice of function references
    let functions = arena.alloc_slice(&[func1, func2]);

    assert_eq!(functions.len(), 2);
    assert_eq!(functions[0].name, "func1");
    assert_eq!(functions[1].name, "func2");
}

#[test]
fn test_arena_lifetime_safety() {
    let arena = Arena::new();

    let contract = {
        let temp_name = "TemporaryContract";
        // This should work - arena-allocated string outlives the temporary
        arena.alloc(Contract {
            name: arena.alloc_str(temp_name),
            functions: arena.alloc_slice(&[]),
            state_variables: arena.alloc_slice(&[]),
            events: arena.alloc_slice(&[]),
            modifiers: arena.alloc_slice(&[]),
            inheritance: arena.alloc_slice(&[]),
            location: Default::default(),
            contract_type: ast::ContractType::Contract,
        })
    };

    // Contract should still be valid here
    assert_eq!(contract.name, "TemporaryContract");
}

#[test]
fn test_arena_large_allocation() {
    let arena = Arena::new();

    // Test allocation of large structures
    const LARGE_SIZE: usize = 1000;

    let mut functions = Vec::new();
    for i in 0..LARGE_SIZE {
        let name = format!("function_{}", i);
        let function = arena.alloc(Function {
            name: arena.alloc_str(&name),
            visibility: ast::Visibility::Public,
            mutability: ast::StateMutability::Pure,
            parameters: arena.alloc_slice(&[]),
            returns: arena.alloc_slice(&[]),
            body: None,
            modifiers: arena.alloc_slice(&[]),
            location: Default::default(),
        });
        functions.push(function);
    }

    let functions_slice = arena.alloc_slice(&functions);

    let contract = arena.alloc(Contract {
        name: arena.alloc_str("LargeContract"),
        functions: functions_slice,
        state_variables: arena.alloc_slice(&[]),
        events: arena.alloc_slice(&[]),
        modifiers: arena.alloc_slice(&[]),
        inheritance: arena.alloc_slice(&[]),
        location: Default::default(),
        contract_type: ast::ContractType::Contract,
    });

    assert_eq!(contract.functions.len(), LARGE_SIZE);
    assert_eq!(contract.functions[0].name, "function_0");
    assert_eq!(contract.functions[LARGE_SIZE - 1].name, "function_999");
}

#[test]
fn test_arena_memory_usage() {
    // Test that arena uses less memory than equivalent heap allocations
    let arena = Arena::new();

    // Get initial memory usage
    let initial_bytes = arena.allocated_bytes();

    // Allocate some data
    let _str1 = arena.alloc_str("test string 1");
    let _str2 = arena.alloc_str("test string 2");
    let _contract = arena.alloc(Contract {
        name: arena.alloc_str("TestContract"),
        functions: arena.alloc_slice(&[]),
        state_variables: arena.alloc_slice(&[]),
        events: arena.alloc_slice(&[]),
        modifiers: arena.alloc_slice(&[]),
        inheritance: arena.alloc_slice(&[]),
        location: Default::default(),
        contract_type: ast::ContractType::Contract,
    });

    let final_bytes = arena.allocated_bytes();
    let used_bytes = final_bytes - initial_bytes;

    // Should have allocated something
    assert!(used_bytes > 0);

    // Should be reasonable amount (less than 1KB for this test)
    assert!(used_bytes < 1024);
}

#[test]
fn test_arena_concurrent_safety() {
    use std::sync::Arc;
    use std::thread;

    // Test that arena can be safely shared between threads (read-only)
    let arena = Arc::new(Arena::new());

    let contract = arena.alloc(Contract {
        name: arena.alloc_str("SharedContract"),
        functions: arena.alloc_slice(&[]),
        state_variables: arena.alloc_slice(&[]),
        events: arena.alloc_slice(&[]),
        modifiers: arena.alloc_slice(&[]),
        inheritance: arena.alloc_slice(&[]),
        location: Default::default(),
        contract_type: ast::ContractType::Contract,
    });

    let handles: Vec<_> = (0..4)
        .map(|i| {
            let arena_clone = Arc::clone(&arena);
            let contract_ptr = contract as *const Contract;

            thread::spawn(move || {
                // Read from arena-allocated data
                let contract_ref = unsafe { &*contract_ptr };
                assert_eq!(contract_ref.name, "SharedContract");
                println!("Thread {} accessed contract: {}", i, contract_ref.name);
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }
}