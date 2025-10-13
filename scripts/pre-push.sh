#!/bin/bash
# Pre-push validation script for SolidityDefend
# Runs all CI checks locally to prevent wasted GitHub Actions minutes

set -e  # Exit on first error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}SolidityDefend Pre-Push Validation${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Track overall success
FAILED=0

# Function to run a check
run_check() {
    local name="$1"
    local cmd="$2"

    echo -e "${YELLOW}Running: ${name}${NC}"
    if eval "$cmd"; then
        echo -e "${GREEN}✓ ${name} passed${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}✗ ${name} failed${NC}"
        echo ""
        FAILED=1
        return 1
    fi
}

# 1. Format check
run_check "Code formatting" "cargo fmt --all -- --check"

# 2. Clippy
run_check "Clippy linting" "cargo clippy --workspace --all-targets --all-features -- -D warnings"

# 3. Unit tests
run_check "Unit tests" "cargo test --workspace --lib"

# 4. Integration tests
run_check "Integration tests" "cargo test --workspace --test '*'" || true  # Don't fail if no integration tests

# 5. Benchmark compilation
run_check "Benchmark compilation" "cargo bench --no-run --workspace" || true  # Don't fail if no benchmarks

# 6. Release build
run_check "Release build" "cargo build --release --workspace"

# 7. Documentation
run_check "Documentation generation" "cargo doc --workspace --no-deps --quiet"

# Final result
echo -e "${BLUE}======================================${NC}"
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo -e "${GREEN}Safe to push to GitHub${NC}"
    echo -e "${BLUE}======================================${NC}"
    exit 0
else
    echo -e "${RED}✗ Some checks failed!${NC}"
    echo -e "${RED}Fix errors before pushing${NC}"
    echo -e "${BLUE}======================================${NC}"
    exit 1
fi
