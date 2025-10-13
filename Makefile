# SolidityDefend Makefile
# Local CI validation to save GitHub Actions costs

.PHONY: help quick ci-local pre-push fmt fmt-check clippy test test-all bench bench-run build doc clean install

# Default target
help:
	@echo "SolidityDefend Development Commands"
	@echo "===================================="
	@echo ""
	@echo "Quick Validation (Fast - Use During Development):"
	@echo "  make quick         - Fast check: fmt + clippy + unit tests"
	@echo ""
	@echo "Complete CI Validation (Before Push):"
	@echo "  make ci-local      - Full CI validation (same as GitHub Actions)"
	@echo "  make pre-push      - Run pre-push validation script"
	@echo ""
	@echo "Code Quality:"
	@echo "  make fmt           - Auto-format all code"
	@echo "  make fmt-check     - Check code formatting"
	@echo "  make clippy        - Run linter with strict warnings"
	@echo ""
	@echo "Testing:"
	@echo "  make test          - Run unit tests only"
	@echo "  make test-all      - Run all tests (unit + integration)"
	@echo "  make test-detectors - Run detector validation tests"
	@echo ""
	@echo "Performance:"
	@echo "  make bench         - Compile benchmarks"
	@echo "  make bench-run     - Run benchmarks with reports"
	@echo ""
	@echo "Build & Distribution:"
	@echo "  make build         - Release build"
	@echo "  make build-all     - Build all workspace crates"
	@echo "  make doc           - Generate documentation"
	@echo "  make install       - Install binary locally"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean         - Clean build artifacts"
	@echo "  make clean-cache   - Clean analysis caches"
	@echo ""
	@echo "Release (Use with caution):"
	@echo "  make release-check - Validate release readiness"
	@echo "  make release-dry   - Dry run release process"

# Quick validation for development iteration
quick:
	@echo "==> Quick validation (fmt + clippy + test)..."
	@cargo fmt --all -- --check
	@cargo clippy --workspace --all-targets --all-features -- -D warnings
	@cargo test --workspace --lib
	@echo "✓ Quick validation passed!"

# Full CI validation matching GitHub Actions
ci-local:
	@echo "==> Running full CI validation..."
	@echo ""
	@echo "1/7 Checking code formatting..."
	@cargo fmt --all -- --check
	@echo "✓ Format check passed"
	@echo ""
	@echo "2/7 Running clippy linter..."
	@cargo clippy --workspace --all-targets --all-features -- -D warnings
	@echo "✓ Clippy passed"
	@echo ""
	@echo "3/7 Running unit tests..."
	@cargo test --workspace --lib
	@echo "✓ Unit tests passed"
	@echo ""
	@echo "4/7 Running integration tests..."
	@cargo test --workspace --test '*'
	@echo "✓ Integration tests passed"
	@echo ""
	@echo "5/7 Compiling benchmarks..."
	@cargo bench --no-run --workspace
	@echo "✓ Benchmarks compiled"
	@echo ""
	@echo "6/7 Building release binary..."
	@cargo build --release --workspace
	@echo "✓ Release build successful"
	@echo ""
	@echo "7/7 Generating documentation..."
	@cargo doc --workspace --no-deps
	@echo "✓ Documentation generated"
	@echo ""
	@echo "========================================"
	@echo "✓ All CI validation checks passed!"
	@echo "Safe to push to GitHub"
	@echo "========================================"

# Pre-push validation (alternative to ci-local)
pre-push:
	@./scripts/pre-push.sh

# Code formatting
fmt:
	@cargo fmt --all

fmt-check:
	@cargo fmt --all -- --check

# Linting
clippy:
	@cargo clippy --workspace --all-targets --all-features -- -D warnings

# Testing
test:
	@cargo test --workspace --lib

test-all:
	@cargo test --workspace --all-features

test-detectors:
	@echo "==> Running detector validation tests..."
	@cargo test --workspace --all-features -- --test-threads=1
	@echo "✓ Detector tests passed"

# Performance
bench:
	@cargo bench --no-run --workspace

bench-run:
	@cargo bench --workspace

# Build
build:
	@cargo build --release

build-all:
	@cargo build --workspace --release

# Documentation
doc:
	@cargo doc --workspace --no-deps --open

# Installation
install:
	@cargo install --path crates/cli --force

# Cleanup
clean:
	@cargo clean

clean-cache:
	@rm -rf .soliditydefend-cache
	@echo "✓ Cache cleaned"

# Release validation
release-check:
	@echo "==> Validating release readiness..."
	@./scripts/release-check.sh

release-dry:
	@echo "==> Dry run release process..."
	@echo "Current version: $$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)"
	@echo "Recent commits:"
	@git log --oneline -5
	@echo ""
	@echo "Run 'make ci-local' before creating release tag"

# Security audit
audit:
	@cargo audit

# Check for outdated dependencies
outdated:
	@cargo outdated

# Watch for changes and run tests
watch:
	@cargo watch -x "test --workspace"

# Run all detector tests with verbose output
test-verbose:
	@RUST_LOG=debug cargo test --workspace --all-features -- --nocapture
