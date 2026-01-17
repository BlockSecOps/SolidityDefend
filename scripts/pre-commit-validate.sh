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
if cargo test -p tests --test regression_tests --quiet 2>/dev/null; then
    echo -e "${GREEN}✓ Regression tests passed${NC}"
else
    echo -e "${RED}✗ Regression tests FAILED${NC}"
    echo ""
    echo -e "${RED}Your changes may have broken detection of critical vulnerabilities.${NC}"
    echo -e "${YELLOW}Run the following to see details:${NC}"
    echo "  cargo test -p tests --test regression_tests"
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
    if ./target/release/soliditydefend --validate \
        --ground-truth "$GROUND_TRUTH" \
        --fail-on-regression \
        --min-recall 0.90 2>/dev/null; then
        echo -e "${GREEN}✓ Ground truth validation passed${NC}"
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
        exit 1
    fi
fi

echo ""
echo -e "${GREEN}✓ All validation checks passed${NC}"
