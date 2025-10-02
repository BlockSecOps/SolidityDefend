# Architecture Documentation

Technical architecture overview of SolidityDefend's design and implementation.

## Table of Contents

- [Overview](#overview)
- [High-Level Architecture](#high-level-architecture)
- [Core Components](#core-components)
- [Data Flow](#data-flow)
- [Design Patterns](#design-patterns)
- [Performance Architecture](#performance-architecture)
- [Extension Points](#extension-points)
- [Future Architecture](#future-architecture)

## Overview

SolidityDefend is built as a modular Rust workspace using a layered architecture that separates parsing, analysis, and output concerns. The design emphasizes performance, extensibility, and maintainability.

### Key Design Principles

1. **Modularity**: Each crate has a single responsibility
2. **Performance**: Arena allocation and incremental computation
3. **Extensibility**: Plugin-like detector architecture
4. **Type Safety**: Leveraging Rust's type system for correctness
5. **Memory Efficiency**: Careful memory management for large codebases

### Project Statistics

- **Total Lines of Code**: ~27,200+ lines
- **Source Files**: 88 Rust files
- **Crates**: 18 modular components
- **Test Infrastructure**: 150+ comprehensive tests covering entire analysis pipeline
- **Detectors**: 17 production-ready security detectors

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SolidityDefend CLI                      │
├─────────────────────────────────────────────────────────────────┤
│  User Interface Layer                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐│
│  │     CLI      │  │     LSP      │  │   Future: Web UI      ││
│  │   (clap)     │  │  (tower)     │  │                        ││
│  └──────────────┘  └──────────────┘  └────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│  Output Layer                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐│
│  │   Console    │  │     JSON     │  │        SARIF           ││
│  │  Formatter   │  │  Formatter   │  │      Formatter         ││
│  └──────────────┘  └──────────────┘  └────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│  Analysis Layer                                                │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐│
│  │  Detectors   │  │   Fixes      │  │     Performance        ││
│  │  Registry    │  │   Engine     │  │    Optimization        ││
│  └──────────────┘  └──────────────┘  └────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│  Analysis Infrastructure                                       │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐│
│  │   DataFlow   │  │     CFG      │  │         IR             ││
│  │   Analysis   │  │ Construction │  │   (Intermediate        ││
│  │              │  │              │  │  Representation)       ││
│  └──────────────┘  └──────────────┘  └────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│  Core Infrastructure                                           │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐│
│  │   Semantic   │  │   Database   │  │        Cache           ││
│  │   Analysis   │  │   (Salsa)    │  │      Manager           ││
│  └──────────────┘  └──────────────┘  └────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│  Foundation Layer                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐│
│  │    Parser    │  │     AST      │  │       Metrics          ││
│  │  (solang)    │  │   (Arena)    │  │    Collection          ││
│  └──────────────┘  └──────────────┘  └────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### Foundation Layer

#### Parser (`crates/parser`)
**Purpose**: Converts Solidity source code into Abstract Syntax Trees

**Key Features**:
- Integration with `solang-parser` for robust Solidity parsing
- Error recovery for partial analysis of invalid code
- Multi-file parsing with dependency resolution
- Source location tracking for precise error reporting

**Architecture**:
```rust
pub struct Parser {
    arena: Arc<AstArena>,
    error_recovery: bool,
}

impl Parser {
    pub fn parse_file(&self, path: &Path) -> Result<SourceUnit>;
    pub fn parse_content(&self, content: &str) -> Result<SourceUnit>;
}
```

#### AST (`crates/ast`)
**Purpose**: Memory-efficient Abstract Syntax Tree representation

**Key Features**:
- Arena allocation using `bumpalo` for fast allocation/deallocation
- Comprehensive Solidity AST node definitions
- Source location preservation
- Memory usage estimation and tracking

**Architecture**:
```rust
pub struct AstArena {
    arena: Bump,
    memory_tracker: MemoryTracker,
}

// All AST nodes allocated in arena
pub struct SourceUnit<'a> {
    pub contracts: &'a [ContractDefinition<'a>],
    pub imports: &'a [ImportDirective<'a>],
}
```

### Core Infrastructure

#### Database (`crates/db`)
**Purpose**: Incremental computation and caching foundation

**Key Features**:
- Simplified Salsa-like incremental computation
- Content-based caching with hash tracking
- Dependency invalidation
- Memory pressure monitoring

**Architecture**:
```rust
pub struct Database {
    files: DashMap<PathBuf, FileEntry>,
    cache: DashMap<ContentHash, CachedResult>,
    dependency_graph: DashMap<PathBuf, HashSet<PathBuf>>,
}
```

#### Semantic Analysis (`crates/semantic`)
**Purpose**: Symbol resolution and type checking

**Key Features**:
- Symbol table construction and management
- Name resolution across contracts and imports
- Type checking and validation
- Inheritance analysis

**Architecture**:
```rust
pub struct SymbolTable {
    scopes: Vec<Scope>,
    symbols: HashMap<String, Symbol>,
    types: HashMap<TypeId, TypeInfo>,
}

pub struct NameResolver<'a> {
    symbol_table: &'a mut SymbolTable,
    current_scope: ScopeId,
}
```

### Analysis Infrastructure

#### IR (`crates/ir`)
**Purpose**: Intermediate representation for advanced analysis

**Key Features**:
- SSA-form (Static Single Assignment) representation
- Comprehensive instruction set for Solidity operations
- Lowering from AST to IR
- Optimization passes

**Architecture**:
```rust
pub enum Instruction {
    Assign { target: ValueId, source: ValueId },
    Call { function: ValueId, args: Vec<ValueId> },
    Load { target: ValueId, address: ValueId },
    // ... other instructions
}

pub struct Function {
    pub blocks: Vec<BasicBlock>,
    pub entry_block: BlockId,
}
```

#### CFG (`crates/cfg`)
**Purpose**: Control Flow Graph construction and analysis

**Key Features**:
- Basic block identification and construction
- Dominance analysis for advanced optimizations
- Natural loop detection
- Graph traversal utilities

**Architecture**:
```rust
pub struct ControlFlowGraph {
    pub blocks: Vec<BasicBlock>,
    pub edges: Vec<Edge>,
    dominance_tree: DominanceTree,
}

pub struct BasicBlock {
    pub id: BlockId,
    pub instructions: Vec<Instruction>,
    pub predecessors: Vec<BlockId>,
    pub successors: Vec<BlockId>,
}
```

#### DataFlow (`crates/dataflow`)
**Purpose**: Data flow analysis framework

**Key Features**:
- Taint analysis for security vulnerabilities
- Reaching definitions analysis
- Live variable analysis
- Def-use chain construction

**Architecture**:
```rust
pub trait DataFlowAnalysis {
    type State: Clone + PartialEq;

    fn initial_state(&self) -> Self::State;
    fn transfer_block(&self, state: &Self::State, block: &BasicBlock) -> Self::State;
    fn merge_states(&self, states: &[Self::State]) -> Self::State;
}

pub struct TaintAnalysis {
    sources: HashSet<String>,
    sinks: HashSet<String>,
    sanitizers: HashSet<String>,
}
```

### Analysis Layer

#### Detectors (`crates/detectors`)
**Purpose**: Security vulnerability detection engines

**Key Features**:
- Modular detector architecture with trait-based design
- Automatic detector registration and discovery
- Configurable severity levels and confidence ratings
- Rich finding metadata with fix suggestions

**Architecture**:
```rust
pub trait Detector: Send + Sync {
    fn detect(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>>;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
}

pub struct DetectorRegistry {
    detectors: Vec<Arc<dyn Detector>>,
    enabled_detectors: HashSet<String>,
}

// Example detector implementation
pub struct ClassicReentrancyDetector;

impl Detector for ClassicReentrancyDetector {
    fn detect(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        // Detection logic
    }
}
```

#### Fixes (`crates/fixes`)
**Purpose**: Automatic fix suggestions and code transformations

**Key Features**:
- Text-based and semantic-based fix suggestions
- Integration with detectors for specific fixes
- Code transformation utilities
- Fix validation and testing

**Architecture**:
```rust
pub trait FixGenerator: Send + Sync {
    fn generate_fixes(&self, finding: &Finding, ctx: &AnalysisContext) -> Result<Vec<FixSuggestion>>;
}

pub struct FixSuggestion {
    pub description: String,
    pub replacements: Vec<TextReplacement>,
    pub confidence: FixConfidence,
}
```

### Performance Architecture

#### Cache (`crates/cache`)
**Purpose**: Persistent caching for faster analysis

**Key Features**:
- Content-based cache keys using Blake3 hashing
- LRU eviction with memory pressure monitoring
- Dependency-aware invalidation
- Persistent storage with compression

**Architecture**:
```rust
pub struct CacheManager {
    memory_cache: LruCache<CacheKey, CachedValue>,
    disk_cache: DiskCache,
    invalidation_tracker: InvalidationTracker,
}
```

#### Performance (`crates/performance`)
**Purpose**: Performance optimization framework

**Key Features**:
- Incremental analysis with file change tracking
- Parallel detector execution when safe
- Memory management and garbage collection
- Streaming analysis for large files

**Architecture**:
```rust
pub struct PerformanceManager {
    incremental_analyzer: IncrementalAnalyzer,
    parallel_executor: ParallelExecutor,
    memory_manager: MemoryManager,
    streaming_analyzer: StreamingAnalyzer,
}
```

### Testing Infrastructure

#### Analysis Tests (`crates/analysis/tests`)
**Purpose**: Comprehensive testing infrastructure for the analysis engine

**Key Features**:
- **Integration Tests**: Complete AST → IR → CFG → Dataflow pipeline validation
- **Test Fixtures**: Arena-allocated AST test fixtures for realistic scenarios
- **Performance Benchmarks**: Scalability testing for large codebases (up to 10,000+ lines)
- **Regression Tests**: Automated security detector accuracy validation

**Architecture**:
```rust
pub struct TestFixtures {
    arena: AstArena,
    parser: Parser,
}

impl TestFixtures {
    pub fn simple_contract(&self) -> AnalysisResult<&SourceUnit>;
    pub fn erc20_contract(&self) -> AnalysisResult<&SourceUnit>;
    pub fn defi_protocol(&self) -> AnalysisResult<&SourceUnit>;
    pub fn complex_contract(&self) -> AnalysisResult<&SourceUnit>;
}

pub struct PerformanceBenchmarks;

impl PerformanceBenchmarks {
    pub fn benchmark_simple_analysis() -> BenchmarkResult;
    pub fn benchmark_medium_complexity() -> BenchmarkResult;
    pub fn benchmark_high_complexity() -> BenchmarkResult;
    pub fn benchmark_very_high_complexity() -> BenchmarkResult;
}
```

**Test Coverage**:
- **Integration Tests**: 4 comprehensive tests validating complete analysis pipeline
- **Test Fixtures**: 15+ predefined Solidity contract patterns
- **Performance Tests**: 4 scalability benchmarks from simple to very high complexity
- **Regression Tests**: Automated validation with performance thresholds

### Output Layer

#### Output (`crates/output`)
**Purpose**: Multi-format result formatting and presentation

**Key Features**:
- Console formatter with colors and code snippets
- JSON formatter for machine processing
- SARIF formatter for tool interoperability
- Extensible formatter architecture

**Architecture**:
```rust
pub trait OutputFormatter {
    fn format(&self, findings: &[Finding]) -> Result<String>;
}

pub struct ConsoleFormatter {
    use_colors: bool,
    include_snippets: bool,
    width: usize,
}
```

## Data Flow

### Analysis Pipeline

```
Source Files
     │
     ▼
┌─────────────┐
│   Parser    │ ──► AST (Arena)
└─────────────┘
     │
     ▼
┌─────────────┐
│  Database   │ ──► Incremental Updates
└─────────────┘
     │
     ▼
┌─────────────┐
│  Semantic   │ ──► Symbol Tables
│  Analysis   │     Type Information
└─────────────┘
     │
     ▼
┌─────────────┐
│     IR      │ ──► SSA Form
│  Lowering   │     Instructions
└─────────────┘
     │
     ▼
┌─────────────┐
│    CFG      │ ──► Control Flow
│Construction │     Basic Blocks
└─────────────┘
     │
     ▼
┌─────────────┐
│  DataFlow   │ ──► Taint Analysis
│  Analysis   │     Def-Use Chains
└─────────────┘
     │
     ▼
┌─────────────┐
│  Detectors  │ ──► Security Findings
│  Registry   │     Vulnerabilities
└─────────────┘
     │
     ▼
┌─────────────┐
│    Fixes    │ ──► Fix Suggestions
│   Engine    │     Code Changes
└─────────────┘
     │
     ▼
┌─────────────┐
│   Output    │ ──► Console/JSON/SARIF
│ Formatters  │     Reports
└─────────────┘
```

### Memory Management Flow

```
┌─────────────┐
│   Source    │
│    Files    │
└─────────────┘
     │
     ▼
┌─────────────┐    Arena Allocation
│   Parser    │ ──────────────────► ┌─────────────┐
└─────────────┘                     │ AST Arena   │
     │                              │ (bumpalo)   │
     ▼                              └─────────────┘
┌─────────────┐    Symbol Tables           │
│  Semantic   │ ──────────────────► ┌─────────────┐
│  Analysis   │                     │ Hash Maps   │
└─────────────┘                     │ Vec Storage │
     │                              └─────────────┘
     ▼                                     │
┌─────────────┐    Analysis Results        │
│  Detectors  │ ──────────────────► ┌─────────────┐
└─────────────┘                     │   Cache     │
     │                              │ (LRU + Disk)│
     ▼                              └─────────────┘
┌─────────────┐    Formatted Output       │
│   Output    │ ◄──────────────────────────┘
└─────────────┘
     │
     ▼
┌─────────────┐    Memory Cleanup
│ Garbage     │ (Arena Drop + Cache Eviction)
│ Collection  │
└─────────────┘
```

## Design Patterns

### 1. Arena Allocation Pattern

**Purpose**: Efficient memory management for tree structures

```rust
// All AST nodes allocated in a single arena
pub struct AstArena {
    arena: Bump,
}

impl AstArena {
    pub fn alloc<T>(&self, value: T) -> &T {
        self.arena.alloc(value)
    }

    pub fn alloc_slice<T>(&self, slice: &[T]) -> &[T]
    where T: Clone {
        self.arena.alloc_slice_clone(slice)
    }
}

// Usage in AST construction
impl<'a> AstBuilder<'a> {
    fn build_contract(&self, node: solang_parser::pt::ContractDefinition)
        -> &'a ContractDefinition<'a> {
        self.arena.alloc(ContractDefinition {
            name: self.arena.alloc_str(&node.name.name),
            functions: self.build_functions(&node.functions),
        })
    }
}
```

### 2. Plugin Architecture Pattern

**Purpose**: Extensible detector system

```rust
// Base trait for all detectors
pub trait Detector: Send + Sync {
    fn detect(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>>;
    fn name(&self) -> &'static str;
    fn severity(&self) -> Severity { Severity::Medium }
}

// Registry with automatic discovery
pub struct DetectorRegistry {
    detectors: Vec<Arc<dyn Detector>>,
}

impl DetectorRegistry {
    pub fn with_all_detectors() -> Self {
        let mut registry = Self::new();

        // Automatic registration
        registry.register(Arc::new(ClassicReentrancyDetector));
        registry.register(Arc::new(MissingAccessControlDetector));
        // ... more detectors

        registry
    }
}
```

### 3. Visitor Pattern

**Purpose**: AST traversal and analysis

```rust
pub trait AstVisitor<'a> {
    fn visit_source_unit(&mut self, unit: &SourceUnit<'a>) {
        walk_source_unit(self, unit);
    }

    fn visit_contract(&mut self, contract: &ContractDefinition<'a>) {
        walk_contract(self, contract);
    }

    fn visit_function(&mut self, function: &FunctionDefinition<'a>) {
        walk_function(self, function);
    }
}

// Example detector using visitor pattern
pub struct ReentrancyDetector {
    findings: Vec<Finding>,
    in_external_call: bool,
}

impl<'a> AstVisitor<'a> for ReentrancyDetector {
    fn visit_function_call(&mut self, call: &FunctionCall<'a>) {
        if self.is_external_call(call) {
            self.in_external_call = true;
        }
        walk_function_call(self, call);
        self.in_external_call = false;
    }

    fn visit_assignment(&mut self, assignment: &Assignment<'a>) {
        if self.in_external_call && self.modifies_state(assignment) {
            self.findings.push(self.create_reentrancy_finding(assignment));
        }
    }
}
```

### 4. Builder Pattern

**Purpose**: Complex object construction

```rust
pub struct FindingBuilder {
    id: Option<String>,
    detector: Option<String>,
    title: Option<String>,
    description: Option<String>,
    severity: Severity,
    location: Option<SourceLocation>,
}

impl FindingBuilder {
    pub fn new() -> Self {
        Self {
            severity: Severity::Medium,
            ..Default::default()
        }
    }

    pub fn detector(mut self, detector: &str) -> Self {
        self.detector = Some(detector.to_string());
        self
    }

    pub fn title(mut self, title: &str) -> Self {
        self.title = Some(title.to_string());
        self
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn build(self) -> Result<Finding> {
        Ok(Finding {
            id: self.id.ok_or("Missing id")?,
            detector: self.detector.ok_or("Missing detector")?,
            title: self.title.ok_or("Missing title")?,
            description: self.description.unwrap_or_default(),
            severity: self.severity,
            location: self.location,
        })
    }
}
```

### 5. Strategy Pattern

**Purpose**: Configurable analysis strategies

```rust
pub trait AnalysisStrategy {
    fn analyze(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>>;
}

pub struct QuickAnalysis;
pub struct DeepAnalysis;
pub struct ComprehensiveAnalysis;

impl AnalysisStrategy for QuickAnalysis {
    fn analyze(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        // Fast analysis with basic detectors
    }
}

impl AnalysisStrategy for DeepAnalysis {
    fn analyze(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        // Thorough analysis with dataflow
    }
}

pub struct Analyzer {
    strategy: Box<dyn AnalysisStrategy>,
}

impl Analyzer {
    pub fn with_strategy(strategy: Box<dyn AnalysisStrategy>) -> Self {
        Self { strategy }
    }

    pub fn analyze(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        self.strategy.analyze(ctx)
    }
}
```

## Performance Architecture

### Memory Management Strategy

1. **Arena Allocation**: All AST nodes in a single memory arena
2. **Reference Counting**: Shared ownership for expensive computations
3. **Lazy Loading**: On-demand loading of analysis results
4. **Cache Eviction**: LRU-based memory pressure management

### Incremental Computation

```rust
pub struct IncrementalAnalyzer {
    file_states: DashMap<PathBuf, FileState>,
    dependency_graph: DashMap<PathBuf, HashSet<PathBuf>>,
    analysis_cache: LruCache<ContentHash, AnalysisResult>,
}

impl IncrementalAnalyzer {
    pub fn analyze_with_changes(&self, changed_files: &[PathBuf]) -> Result<AnalysisResult> {
        // 1. Identify affected files through dependency graph
        let affected_files = self.compute_affected_files(changed_files)?;

        // 2. Invalidate cached results for affected files
        self.invalidate_cache(&affected_files);

        // 3. Analyze only changed and affected files
        let mut results = Vec::new();
        for file in affected_files {
            if let Some(cached) = self.get_cached_result(&file) {
                results.push(cached);
            } else {
                let result = self.analyze_file(&file)?;
                self.cache_result(&file, &result);
                results.push(result);
            }
        }

        // 4. Merge results
        Ok(self.merge_results(results))
    }
}
```

### Parallel Processing

```rust
pub struct ParallelAnalyzer {
    thread_pool: ThreadPool,
    detector_registry: Arc<DetectorRegistry>,
}

impl ParallelAnalyzer {
    pub fn analyze_parallel(&self, files: &[PathBuf]) -> Result<Vec<Finding>> {
        let (sender, receiver) = crossbeam_channel::unbounded();

        // Distribute files across worker threads
        for chunk in files.chunks(self.chunk_size()) {
            let chunk = chunk.to_vec();
            let registry = Arc::clone(&self.detector_registry);
            let sender = sender.clone();

            self.thread_pool.execute(move || {
                let mut findings = Vec::new();
                for file in chunk {
                    if let Ok(file_findings) = Self::analyze_file(&file, &registry) {
                        findings.extend(file_findings);
                    }
                }
                let _ = sender.send(findings);
            });
        }

        // Collect results from all threads
        drop(sender);
        let mut all_findings = Vec::new();
        for findings in receiver {
            all_findings.extend(findings);
        }

        Ok(all_findings)
    }
}
```

## Extension Points

### Adding New Detectors

1. **Implement Detector Trait**:
```rust
pub struct MyCustomDetector;

impl Detector for MyCustomDetector {
    fn detect(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        // Custom detection logic
    }

    fn name(&self) -> &'static str {
        "my-custom-detector"
    }
}
```

2. **Register in Registry**:
```rust
impl DetectorRegistry {
    pub fn with_all_detectors() -> Self {
        let mut registry = Self::new();
        // ... existing detectors
        registry.register(Arc::new(MyCustomDetector));
        registry
    }
}
```

### Adding New Output Formats

1. **Implement OutputFormatter Trait**:
```rust
pub struct XmlFormatter;

impl OutputFormatter for XmlFormatter {
    fn format(&self, findings: &[Finding]) -> Result<String> {
        // XML formatting logic
    }
}
```

2. **Integrate with CLI**:
```rust
match format.as_str() {
    "console" => Box::new(ConsoleFormatter::new()),
    "json" => Box::new(JsonFormatter::new()),
    "sarif" => Box::new(SarifFormatter::new()),
    "xml" => Box::new(XmlFormatter::new()),
    _ => return Err("Unsupported format"),
}
```

### Adding New Analysis Passes

1. **Implement DataFlowAnalysis**:
```rust
pub struct MyAnalysis;

impl DataFlowAnalysis for MyAnalysis {
    type State = MyState;

    fn initial_state(&self) -> Self::State {
        MyState::new()
    }

    fn transfer_block(&self, state: &Self::State, block: &BasicBlock) -> Self::State {
        // Transfer function logic
    }
}
```

## Future Architecture

### Planned Enhancements

1. **Full Salsa Integration**: Complete incremental computation system
2. **Plugin System**: Dynamic loading of external detectors
3. **Distributed Analysis**: Multi-machine analysis for very large codebases
4. **Machine Learning Integration**: AI-powered false positive reduction
5. **Real-time Analysis**: File system watching and immediate feedback

### Architectural Evolution

```
Current Architecture (v0.1)
├── Static Analysis Only
├── Single-threaded Core
├── Simple Caching
└── File-based Processing

Future Architecture (v1.0+)
├── Dynamic Analysis Integration
├── Full Parallel Processing
├── Advanced Incremental Computation
├── Streaming + Real-time Analysis
├── Cloud-native Deployment
└── AI/ML Enhancement
```

### Scalability Considerations

1. **Memory Scaling**: Handle projects with 10,000+ files
2. **Computation Scaling**: Distribute analysis across multiple cores/machines
3. **Storage Scaling**: Efficient caching for enterprise-scale deployments
4. **Network Scaling**: Remote analysis and cloud integration

## See Also

- [Installation Guide](INSTALLATION.md) - Setting up the development environment
- [Usage Guide](USAGE.md) - How to use the tool effectively
- [Configuration Guide](CONFIGURATION.md) - Configuring the analysis system
- [Detector Documentation](DETECTORS.md) - Understanding the detector architecture
- [Contributing Guidelines](../CONTRIBUTING.md) - How to contribute to the project