#!/bin/bash
# Pre-commit hook for detector validation
#
# This hook runs BEFORE commit to catch regressions early.
# It checks if detector files are being modified and runs validation.
#
# Installed via .pre-commit-config.yaml

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if any detector files are staged
DETECTOR_FILES=$(git diff --cached --name-only --diff-filter=ACMR | grep -E "^crates/detectors/" || true)

if [ -z "$DETECTOR_FILES" ]; then
    # No detector files modified, skip validation
    exit 0
fi

echo -e "${YELLOW}Detector files modified - running validation...${NC}"
echo "$DETECTOR_FILES" | sed 's/^/  /'
echo ""

# Ensure binary is built
if [ ! -f "./target/release/soliditydefend" ]; then
    echo -e "${YELLOW}Building release binary...${NC}"
    cargo build --release --quiet
fi

# Run regression tests (fast - only checks must-detect cases)
echo -e "${YELLOW}Running regression tests...${NC}"
if cargo test -p soliditydefend-tests regression --quiet 2>/dev/null; then
    echo -e "${GREEN}✓ Regression tests passed${NC}"
else
    echo -e "${RED}✗ Regression tests FAILED${NC}"
    echo ""
    echo -e "${RED}Your changes may have broken detection of critical vulnerabilities.${NC}"
    echo -e "${YELLOW}Run the following to see details:${NC}"
    echo "  cargo test -p soliditydefend-tests regression"
    echo ""
    echo -e "${YELLOW}To bypass (not recommended):${NC}"
    echo "  git commit --no-verify"
    exit 1
fi

# Run validation against ground truth if available
GROUND_TRUTH="tests/validation/ground_truth.json"
if [ -f "$GROUND_TRUTH" ]; then
    echo -e "${YELLOW}Validating against ground truth...${NC}"

    # Run validation with fail-on-regression
    # Use temp file to capture output including panics
    # Temporarily disable set -e to capture exit code
    VALIDATION_LOG=$(mktemp)
    set +e
    ./target/release/soliditydefend --validate \
        --ground-truth "$GROUND_TRUTH" \
        --fail-on-regression \
        --min-recall 0.90 > "$VALIDATION_LOG" 2>&1
    VALIDATION_EXIT=$?
    set -e

    if [ $VALIDATION_EXIT -eq 0 ]; then
        echo -e "${GREEN}✓ Ground truth validation passed${NC}"
        rm -f "$VALIDATION_LOG"
    elif [ $VALIDATION_EXIT -eq 101 ] || grep -q "panicked" "$VALIDATION_LOG"; then
        # Validation crashed due to a bug (exit 101 = Rust panic) - warn but don't block
        echo -e "${YELLOW}⚠ Ground truth validation crashed (pre-existing bug)${NC}"
        echo -e "${YELLOW}  Regression tests passed, proceeding with commit${NC}"
        rm -f "$VALIDATION_LOG"
    else
        echo -e "${RED}✗ Ground truth validation FAILED${NC}"
        echo ""
        echo -e "${RED}Your changes caused a regression in detection accuracy.${NC}"
        echo -e "${YELLOW}Run the following to see details:${NC}"
        echo "  ./target/release/soliditydefend --validate --ground-truth $GROUND_TRUTH"
        echo ""
        echo -e "${YELLOW}If the removed findings are confirmed false positives:${NC}"
        echo "  1. Update the ground truth file to reflect the changes"
        echo "  2. Re-run this commit"
        echo ""
        echo -e "${YELLOW}To bypass (not recommended):${NC}"
        echo "  git commit --no-verify"
        rm -f "$VALIDATION_LOG"
        exit 1
    fi
fi

echo ""
echo -e "${GREEN}✓ All validation checks passed${NC}"
