# SolidityDefend

[![CI](https://github.com/soliditydefend/cli/workflows/CI/badge.svg)](https://github.com/soliditydefend/cli/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/soliditydefend/cli#license)
[![Rust Version](https://img.shields.io/badge/rustc-1.75+-blue.svg)](https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html)

A high-performance static analysis security tool for Solidity smart contracts, built with Rust for speed and accuracy.

## Development Status

🚧 **This project is currently in active development as part of Sprint 1: Project Setup and Parser Foundation.**

Current implementation status:
- ✅ Rust workspace structure established
- ✅ Core dependencies configured (salsa, solang-parser, petgraph, rayon, clap)
- ✅ Development tools configured (Clippy, rustfmt, CI/CD)
- ✅ GitHub repository structure established
- 🚧 Parser implementation (T1.2 - next)
- 🚧 Testing foundation (T1.3 - planned)

## Architecture

SolidityDefend is built as a modular Rust workspace with the following components:

- **Parser**: Solidity parser with arena allocation and error recovery
- **AST**: Arena-allocated Abstract Syntax Tree for memory efficiency
- **Database**: Salsa-based incremental computation system
- **Semantic**: Symbol resolution and type checking
- **IR**: SSA-form Intermediate Representation
- **CFG**: Control Flow Graph construction and analysis
- **DataFlow**: Taint tracking and data flow analysis framework
- **Detectors**: Vulnerability detection engine with 75+ planned detectors
- **Output**: Multi-format output (Console, JSON, SARIF, HTML)
- **CLI**: Command-line interface and configuration
- **LSP**: Language Server Protocol for IDE integration

## Development

### Prerequisites

- Rust 1.75.0 or later
- Git

### Building

```bash
# Build workspace
cargo build --release

# Run tests
cargo test --all-features

# Check formatting and linting
cargo fmt --check
cargo clippy -- -D warnings
```

## License

Licensed under either of

 * Apache License, Version 2.0
 * MIT license

at your option.
