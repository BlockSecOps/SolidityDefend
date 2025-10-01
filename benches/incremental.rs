use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;
use db::{Database, SourceFileId};
use parser::Parser;
use ast::AstArena;

/// Incremental analysis benchmark
/// Measures the performance benefits of Salsa's incremental computation

fn setup_database_with_files() -> (Database, Vec<SourceFileId>) {
    let mut db = Database::new();
    let mut file_ids = Vec::new();

    // Create a set of interconnected contracts
    let contracts = vec![
        ("Base.sol", r#"
            pragma solidity ^0.8.0;
            contract Base {
                uint256 public baseValue;
                function baseFunction() public virtual returns (uint256) {
                    return baseValue;
                }
            }
        "#),
        ("Token.sol", r#"
            pragma solidity ^0.8.0;
            import "./Base.sol";
            contract Token is Base {
                string public name;
                uint256 public totalSupply;
                mapping(address => uint256) public balances;

                constructor(string memory _name, uint256 _supply) {
                    name = _name;
                    totalSupply = _supply;
                }

                function transfer(address to, uint256 amount) public returns (bool) {
                    require(balances[msg.sender] >= amount, "Insufficient balance");
                    balances[msg.sender] -= amount;
                    balances[to] += amount;
                    return true;
                }

                function baseFunction() public override returns (uint256) {
                    return totalSupply;
                }
            }
        "#),
        ("DEX.sol", r#"
            pragma solidity ^0.8.0;
            import "./Token.sol";
            contract DEX {
                Token public token;
                uint256 public rate = 100;

                constructor(address _token) {
                    token = Token(_token);
                }

                function swap(uint256 amount) public payable {
                    require(msg.value == amount * rate, "Incorrect payment");
                    token.transfer(msg.sender, amount);
                }

                function getPrice(uint256 amount) public view returns (uint256) {
                    return amount * rate;
                }
            }
        "#),
        ("Governance.sol", r#"
            pragma solidity ^0.8.0;
            import "./Token.sol";
            import "./DEX.sol";
            contract Governance {
                Token public governanceToken;
                DEX public dex;
                uint256 public proposalCount;

                struct Proposal {
                    string description;
                    uint256 votes;
                    bool executed;
                    mapping(address => bool) hasVoted;
                }

                mapping(uint256 => Proposal) public proposals;

                constructor(address _token, address _dex) {
                    governanceToken = Token(_token);
                    dex = DEX(_dex);
                }

                function createProposal(string memory description) public returns (uint256) {
                    uint256 proposalId = proposalCount++;
                    proposals[proposalId].description = description;
                    return proposalId;
                }

                function vote(uint256 proposalId) public {
                    require(!proposals[proposalId].hasVoted[msg.sender], "Already voted");
                    uint256 balance = governanceToken.balances(msg.sender);
                    require(balance > 0, "No governance tokens");

                    proposals[proposalId].votes += balance;
                    proposals[proposalId].hasVoted[msg.sender] = true;
                }
            }
        "#),
        ("Staking.sol", r#"
            pragma solidity ^0.8.0;
            import "./Token.sol";
            contract Staking {
                Token public stakingToken;
                mapping(address => uint256) public stakes;
                mapping(address => uint256) public rewards;
                uint256 public rewardRate = 10; // 10% per block

                constructor(address _token) {
                    stakingToken = Token(_token);
                }

                function stake(uint256 amount) public {
                    require(stakingToken.balances(msg.sender) >= amount, "Insufficient balance");
                    stakingToken.transfer(address(this), amount);
                    stakes[msg.sender] += amount;
                }

                function unstake(uint256 amount) public {
                    require(stakes[msg.sender] >= amount, "Insufficient staked amount");
                    stakes[msg.sender] -= amount;
                    stakingToken.transfer(msg.sender, amount);
                }

                function claimRewards() public {
                    uint256 reward = calculateReward(msg.sender);
                    rewards[msg.sender] = 0;
                    stakingToken.transfer(msg.sender, reward);
                }

                function calculateReward(address staker) public view returns (uint256) {
                    return stakes[staker] * rewardRate / 100;
                }
            }
        "#),
    ];

    for (filename, content) in contracts {
        let file_id = db.add_source_file(filename, content);
        file_ids.push(file_id);
    }

    (db, file_ids)
}

fn bench_initial_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("initial_parse");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("cold_parse_all_files", |b| {
        b.iter(|| {
            let (mut db, file_ids) = setup_database_with_files();

            // Parse all files from scratch
            for file_id in file_ids {
                let _ = db.parse_source_file(file_id);
            }
        });
    });

    group.finish();
}

fn bench_incremental_updates(c: &mut Criterion) {
    let mut group = c.benchmark_group("incremental_updates");
    group.measurement_time(Duration::from_secs(10));

    let (mut db, file_ids) = setup_database_with_files();

    // Initial parse to warm cache
    for file_id in file_ids.iter() {
        let _ = db.parse_source_file(*file_id);
    }

    group.bench_function("small_change_single_file", |b| {
        let base_file = file_ids[0]; // Base.sol

        b.iter(|| {
            // Make a small change to Base.sol
            let updated_content = r#"
                pragma solidity ^0.8.0;
                contract Base {
                    uint256 public baseValue;
                    uint256 public newValue; // Added line
                    function baseFunction() public virtual returns (uint256) {
                        return baseValue;
                    }
                }
            "#;

            db.update_source_file(base_file, updated_content);
            let _ = db.parse_source_file(base_file);

            // Revert change
            let original_content = r#"
                pragma solidity ^0.8.0;
                contract Base {
                    uint256 public baseValue;
                    function baseFunction() public virtual returns (uint256) {
                        return baseValue;
                    }
                }
            "#;
            db.update_source_file(base_file, original_content);
        });
    });

    group.bench_function("dependent_file_invalidation", |b| {
        let base_file = file_ids[0]; // Base.sol
        let token_file = file_ids[1]; // Token.sol (depends on Base)

        b.iter(|| {
            // Change Base.sol which should invalidate Token.sol
            let updated_base = r#"
                pragma solidity ^0.8.0;
                contract Base {
                    uint256 public baseValue;
                    uint256 public additionalValue; // Added field
                    function baseFunction() public virtual returns (uint256) {
                        return baseValue + additionalValue;
                    }
                }
            "#;

            db.update_source_file(base_file, updated_base);

            // Reparse both files
            let _ = db.parse_source_file(base_file);
            let _ = db.parse_source_file(token_file);
        });
    });

    group.finish();
}

fn bench_cache_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_performance");
    group.measurement_time(Duration::from_secs(5));

    let (mut db, file_ids) = setup_database_with_files();

    // Initial parse
    for file_id in file_ids.iter() {
        let _ = db.parse_source_file(*file_id);
    }

    group.bench_function("cache_hit_performance", |b| {
        b.iter(|| {
            // Repeatedly parse the same file - should hit cache
            for file_id in file_ids.iter() {
                let _ = db.parse_source_file(*file_id);
            }
        });
    });

    group.bench_function("derived_query_caching", |b| {
        b.iter(|| {
            // Run derived queries repeatedly
            for file_id in file_ids.iter() {
                let _ = db.get_all_functions(*file_id);
                let _ = db.get_public_functions(*file_id);
                let _ = db.get_contract_dependencies(*file_id);
            }
        });
    });

    group.finish();
}

fn bench_scalability(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalability");
    group.measurement_time(Duration::from_secs(15));

    for file_count in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("parse_n_files", file_count),
            file_count,
            |b, &file_count| {
                b.iter(|| {
                    let mut db = Database::new();
                    let mut file_ids = Vec::new();

                    // Create many small contracts
                    for i in 0..file_count {
                        let content = format!(
                            r#"
                            pragma solidity ^0.8.0;
                            contract Contract{} {{
                                uint256 public value{};
                                function getValue{}() public view returns (uint256) {{
                                    return value{};
                                }}
                            }}
                            "#,
                            i, i, i, i
                        );

                        let filename = format!("Contract{}.sol", i);
                        let file_id = db.add_source_file(&filename, &content);
                        file_ids.push(file_id);
                    }

                    // Parse all files
                    for file_id in file_ids {
                        let _ = db.parse_source_file(file_id);
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("memory_efficiency", |b| {
        b.iter(|| {
            let (mut db, file_ids) = setup_database_with_files();

            // Parse all files
            for file_id in file_ids.iter() {
                let _ = db.parse_source_file(*file_id);
            }

            // Measure memory usage
            let memory_usage = db.get_memory_usage();
            assert!(memory_usage < 100_000_000); // Should be under 100MB for test files
        });
    });

    group.finish();
}

fn bench_invalidation_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("invalidation_patterns");
    group.measurement_time(Duration::from_secs(10));

    let (mut db, file_ids) = setup_database_with_files();

    // Initial parse
    for file_id in file_ids.iter() {
        let _ = db.parse_source_file(*file_id);
    }

    group.bench_function("cascade_invalidation", |b| {
        let base_file = file_ids[0]; // Base.sol - affects multiple files

        b.iter(|| {
            // Change base contract
            let updated_content = r#"
                pragma solidity ^0.8.0;
                contract Base {
                    uint256 public baseValue;
                    string public name; // Breaking change
                    function baseFunction() public virtual returns (string memory) {
                        return name; // Changed return type
                    }
                }
            "#;

            db.update_source_file(base_file, updated_content);

            // Reparse all dependent files
            for file_id in file_ids.iter() {
                let _ = db.parse_source_file(*file_id);
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_initial_parse,
    bench_incremental_updates,
    bench_cache_performance,
    bench_scalability,
    bench_memory_usage,
    bench_invalidation_patterns,
);

criterion_main!(benches);