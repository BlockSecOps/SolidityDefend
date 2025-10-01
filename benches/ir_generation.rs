/// IR generation benchmarks for T023
/// Benchmarks to measure performance of AST to IR lowering
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use ir::{Lowering, IrFunction};
use ast::SourceFile;
use std::time::Duration;

// Sample Solidity contracts for benchmarking
const SIMPLE_CONTRACT: &str = r#"
contract Simple {
    function add(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
    }
}
"#;

const MEDIUM_CONTRACT: &str = r#"
contract Medium {
    uint256 private value;
    mapping(address => uint256) balances;

    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function getBalance(address account) public view returns (uint256) {
        return balances[account];
    }

    function complexCalculation(uint256 x) public pure returns (uint256) {
        uint256 result = 0;
        for (uint256 i = 0; i < x; i++) {
            result += i * i;
        }
        return result;
    }
}
"#;

const COMPLEX_CONTRACT: &str = r#"
contract Complex {
    struct User {
        address addr;
        uint256 balance;
        bool active;
    }

    User[] public users;
    mapping(address => uint256) userIndex;
    mapping(address => mapping(address => uint256)) allowances;

    modifier onlyActive(address user) {
        require(users[userIndex[user]].active, "User not active");
        _;
    }

    function addUser(address addr) public {
        require(userIndex[addr] == 0, "User already exists");
        users.push(User({
            addr: addr,
            balance: 0,
            active: true
        }));
        userIndex[addr] = users.length - 1;
    }

    function transferWithApproval(address from, address to, uint256 amount)
        public onlyActive(from) onlyActive(to) {
        require(allowances[from][msg.sender] >= amount, "Insufficient allowance");
        require(users[userIndex[from]].balance >= amount, "Insufficient balance");

        allowances[from][msg.sender] -= amount;
        users[userIndex[from]].balance -= amount;
        users[userIndex[to]].balance += amount;
    }

    function batchTransfer(address[] memory recipients, uint256[] memory amounts)
        public {
        require(recipients.length == amounts.length, "Mismatched arrays");

        uint256 totalAmount = 0;
        for (uint256 i = 0; i < amounts.length; i++) {
            totalAmount += amounts[i];
        }

        require(users[userIndex[msg.sender]].balance >= totalAmount, "Insufficient balance");

        for (uint256 i = 0; i < recipients.length; i++) {
            users[userIndex[msg.sender]].balance -= amounts[i];
            users[userIndex[recipients[i]]].balance += amounts[i];
        }
    }
}
"#;

const VERY_COMPLEX_CONTRACT: &str = r#"
contract VeryComplex {
    // Multiple inheritance and complex state management
    struct Position {
        uint256 x;
        uint256 y;
        uint256 z;
    }

    struct Entity {
        Position pos;
        mapping(string => uint256) attributes;
        Entity[] children;
        bool exists;
    }

    mapping(bytes32 => Entity) entities;
    bytes32[] entityIds;
    uint256 constant MAX_DEPTH = 10;

    function createEntity(bytes32 id, uint256 x, uint256 y, uint256 z) public {
        require(!entities[id].exists, "Entity exists");
        entities[id] = Entity({
            pos: Position(x, y, z),
            children: new Entity[](0),
            exists: true
        });
        entityIds.push(id);
    }

    function complexPathfinding(bytes32 start, bytes32 end) public view returns (bytes32[] memory) {
        require(entities[start].exists && entities[end].exists, "Invalid entities");

        bytes32[] memory path = new bytes32[](MAX_DEPTH);
        uint256 pathLength = 0;

        // Simplified A* pathfinding algorithm
        mapping(bytes32 => uint256) distances;
        mapping(bytes32 => bytes32) previous;
        bool[] memory visited = new bool[](entityIds.length);

        for (uint256 depth = 0; depth < MAX_DEPTH; depth++) {
            bytes32 current = findNearestUnvisited(distances, visited);
            if (current == end) break;

            visited[getEntityIndex(current)] = true;

            for (uint256 i = 0; i < entityIds.length; i++) {
                if (!visited[i]) {
                    uint256 newDistance = distances[current] + calculateDistance(current, entityIds[i]);
                    if (newDistance < distances[entityIds[i]] || distances[entityIds[i]] == 0) {
                        distances[entityIds[i]] = newDistance;
                        previous[entityIds[i]] = current;
                    }
                }
            }
        }

        // Reconstruct path
        bytes32 current = end;
        while (current != start && pathLength < MAX_DEPTH) {
            path[pathLength] = current;
            current = previous[current];
            pathLength++;
        }

        return path;
    }

    function findNearestUnvisited(mapping(bytes32 => uint256) storage distances, bool[] memory visited)
        internal view returns (bytes32) {
        bytes32 nearest;
        uint256 minDistance = type(uint256).max;

        for (uint256 i = 0; i < entityIds.length; i++) {
            if (!visited[i] && distances[entityIds[i]] < minDistance) {
                minDistance = distances[entityIds[i]];
                nearest = entityIds[i];
            }
        }

        return nearest;
    }

    function calculateDistance(bytes32 a, bytes32 b) internal view returns (uint256) {
        Position memory posA = entities[a].pos;
        Position memory posB = entities[b].pos;

        uint256 dx = posA.x > posB.x ? posA.x - posB.x : posB.x - posA.x;
        uint256 dy = posA.y > posB.y ? posA.y - posB.y : posB.y - posA.y;
        uint256 dz = posA.z > posB.z ? posA.z - posB.z : posB.z - posA.z;

        return dx * dx + dy * dy + dz * dz; // Squared distance for efficiency
    }

    function getEntityIndex(bytes32 id) internal view returns (uint256) {
        for (uint256 i = 0; i < entityIds.length; i++) {
            if (entityIds[i] == id) return i;
        }
        revert("Entity not found");
    }
}
"#;

fn bench_ir_lowering_simple(c: &mut Criterion) {
    let mut group = c.benchmark_group("ir_lowering_simple");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("simple_contract", |b| {
        b.iter(|| {
            let source_file = parse_solidity_contract(black_box(SIMPLE_CONTRACT));
            let lowering = Lowering::new();

            // This will panic until IR is implemented
            for contract in &source_file.contracts {
                for function in &contract.functions {
                    let _ir_function = lowering.lower_function(function);
                }
            }
        })
    });

    group.finish();
}

fn bench_ir_lowering_medium(c: &mut Criterion) {
    let mut group = c.benchmark_group("ir_lowering_medium");
    group.measurement_time(Duration::from_secs(30));

    group.bench_function("medium_contract", |b| {
        b.iter(|| {
            let source_file = parse_solidity_contract(black_box(MEDIUM_CONTRACT));
            let lowering = Lowering::new();

            for contract in &source_file.contracts {
                for function in &contract.functions {
                    let _ir_function = lowering.lower_function(function);
                }
            }
        })
    });

    group.finish();
}

fn bench_ir_lowering_complex(c: &mut Criterion) {
    let mut group = c.benchmark_group("ir_lowering_complex");
    group.measurement_time(Duration::from_secs(60));

    group.bench_function("complex_contract", |b| {
        b.iter(|| {
            let source_file = parse_solidity_contract(black_box(COMPLEX_CONTRACT));
            let lowering = Lowering::new();

            for contract in &source_file.contracts {
                for function in &contract.functions {
                    let _ir_function = lowering.lower_function(function);
                }
            }
        })
    });

    group.finish();
}

fn bench_ir_lowering_very_complex(c: &mut Criterion) {
    let mut group = c.benchmark_group("ir_lowering_very_complex");
    group.measurement_time(Duration::from_secs(120));

    group.bench_function("very_complex_contract", |b| {
        b.iter(|| {
            let source_file = parse_solidity_contract(black_box(VERY_COMPLEX_CONTRACT));
            let lowering = Lowering::new();

            for contract in &source_file.contracts {
                for function in &contract.functions {
                    let _ir_function = lowering.lower_function(function);
                }
            }
        })
    });

    group.finish();
}

fn bench_ir_lowering_by_function_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("ir_lowering_by_function_size");

    // Generate functions of different sizes
    let function_sizes = vec![10, 50, 100, 500, 1000];

    for size in function_sizes {
        group.bench_with_input(
            BenchmarkId::new("function_instructions", size),
            &size,
            |b, &size| {
                b.iter(|| {
                    let contract = generate_function_with_instructions(black_box(size));
                    let source_file = parse_solidity_contract(&contract);
                    let lowering = Lowering::new();

                    for contract in &source_file.contracts {
                        for function in &contract.functions {
                            let _ir_function = lowering.lower_function(function);
                        }
                    }
                })
            },
        );
    }

    group.finish();
}

fn bench_ssa_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("ssa_construction");

    group.bench_function("ssa_phi_insertion", |b| {
        b.iter(|| {
            let source_file = parse_solidity_contract(black_box(COMPLEX_CONTRACT));
            let lowering = Lowering::new();

            for contract in &source_file.contracts {
                for function in &contract.functions {
                    let ir_function = lowering.lower_function(function);
                    // Benchmark SSA construction specifically
                    let _ssa_form = ir_function.to_ssa_form();
                }
            }
        })
    });

    group.finish();
}

fn bench_ir_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("ir_memory_usage");

    group.bench_function("memory_allocation", |b| {
        b.iter(|| {
            let source_file = parse_solidity_contract(black_box(VERY_COMPLEX_CONTRACT));
            let lowering = Lowering::new();

            let mut ir_functions = Vec::new();
            for contract in &source_file.contracts {
                for function in &contract.functions {
                    let ir_function = lowering.lower_function(function);
                    ir_functions.push(ir_function);
                }
            }

            // Measure memory usage
            let memory_usage = calculate_ir_memory_usage(&ir_functions);
            black_box(memory_usage);
        })
    });

    group.finish();
}

// Helper functions (these will panic until infrastructure is implemented)

fn parse_solidity_contract(code: &str) -> SourceFile {
    // Will use existing parser infrastructure
    panic!("Parser integration not implemented yet")
}

fn generate_function_with_instructions(instruction_count: usize) -> String {
    // Generate a Solidity function with approximately `instruction_count` instructions
    let mut contract = String::from("contract Generated {\n    function test() public {\n");

    for i in 0..instruction_count {
        contract.push_str(&format!("        uint256 var{} = {};\n", i, i));
    }

    contract.push_str("    }\n}");
    contract
}

fn calculate_ir_memory_usage(ir_functions: &[IrFunction]) -> usize {
    // Calculate approximate memory usage of IR functions
    panic!("IR infrastructure not implemented yet")
}

criterion_group!(
    benches,
    bench_ir_lowering_simple,
    bench_ir_lowering_medium,
    bench_ir_lowering_complex,
    bench_ir_lowering_very_complex,
    bench_ir_lowering_by_function_size,
    bench_ssa_construction,
    bench_ir_memory_usage
);

criterion_main!(benches);