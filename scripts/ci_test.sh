#!/bin/bash
# CI Test Script for SolidityDefend
# Tests the security analysis tool against known vulnerable contracts

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔍 SolidityDefend CI Security Analysis Tests${NC}"
echo "=============================================="

# Build the project
echo -e "\n${BLUE}📦 Building SolidityDefend...${NC}"
cargo build --release --workspace

# Test variables
BINARY="./target/release/soliditydefend"
TEST_DIR="tests/contracts"
TOTAL_ISSUES=0
TOTAL_FILES=0
FAILED_TESTS=0

# Test each contract file
echo -e "\n${BLUE}🧪 Running Security Analysis Tests...${NC}"

for contract in "$TEST_DIR"/*.sol; do
    if [ -f "$contract" ]; then
        filename=$(basename "$contract")
        echo -e "\n${YELLOW}Testing: $filename${NC}"

        TOTAL_FILES=$((TOTAL_FILES + 1))

        # Run analysis and capture output (ignore exit code since tool exits 1 on high-severity findings)
        output=$($BINARY "$contract" 2>&1 || true)

        # Check if analysis actually succeeded by looking for expected output format
        if echo "$output" | grep -q "Analysis complete:"; then
            # Extract number of issues found
            issues=$(echo "$output" | grep -o "Issues found: [0-9]*" | grep -o "[0-9]*" || echo "0")
            TOTAL_ISSUES=$((TOTAL_ISSUES + issues))

            echo "  Issues found: $issues"

            # Show sample findings
            if [ "$issues" -gt 0 ]; then
                echo "$output" | grep "●" | head -3 | sed 's/^/  /'
                if [ "$issues" -gt 3 ]; then
                    echo "  ... and $((issues - 3)) more"
                fi
            fi
        else
            echo -e "  ${RED}❌ Analysis failed${NC}"
            echo "$output" | sed 's/^/  /'
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    fi
done

# Validate results
echo -e "\n${BLUE}📊 Test Results Summary${NC}"
echo "========================"
echo "Files analyzed: $TOTAL_FILES"
echo "Total issues found: $TOTAL_ISSUES"
echo "Failed analyses: $FAILED_TESTS"

# Validation checks
VALIDATION_PASSED=true

# Check if we found expected number of issues
if [ "$TOTAL_ISSUES" -lt 11 ]; then
    echo -e "${RED}❌ FAIL: Expected at least 11 security issues, found $TOTAL_ISSUES${NC}"
    VALIDATION_PASSED=false
fi

# Check if any analyses failed
if [ "$FAILED_TESTS" -gt 0 ]; then
    echo -e "${RED}❌ FAIL: $FAILED_TESTS analysis failures${NC}"
    VALIDATION_PASSED=false
fi

# Test specific detectors are working
echo -e "\n${BLUE}🔍 Testing Specific Detectors...${NC}"

# Test access control detector
access_output=$($BINARY "$TEST_DIR/access_control_issues.sol" 2>&1 || true)
access_count=$(echo "$access_output" | grep "missing-access-modifiers\|unprotected-initializer" | wc -l)
if [ "$access_count" -lt 3 ]; then
    echo -e "${RED}❌ FAIL: Access control detectors not working properly${NC}"
    VALIDATION_PASSED=false
else
    echo -e "${GREEN}✅ Access control detectors working${NC}"
fi

# Test that clean contract has few/no issues
clean_output=$($BINARY "$TEST_DIR/clean_contract.sol" 2>&1 || true)
clean_issues=$(echo "$clean_output" | grep -o "Issues found: [0-9]*" | grep -o "[0-9]*" || echo "0")
if [ "$clean_issues" -gt 2 ]; then
    echo -e "${YELLOW}⚠️  WARNING: Clean contract has $clean_issues issues (expected ≤2)${NC}"
else
    echo -e "${GREEN}✅ Clean contract analysis working${NC}"
fi

# Final result
echo -e "\n${BLUE}🏁 Final Validation${NC}"
if [ "$VALIDATION_PASSED" = true ]; then
    echo -e "${GREEN}✅ ALL TESTS PASSED${NC}"
    echo "SolidityDefend security analysis is working correctly!"
    exit 0
else
    echo -e "${RED}❌ TESTS FAILED${NC}"
    echo "SolidityDefend security analysis has issues that need to be fixed."
    exit 1
fi