#!/bin/bash
# Detector Change Validation Script
#
# Run this script BEFORE making changes to a detector to:
# 1. Get baseline findings
# 2. Review which findings will be affected
# 3. After changes, compare to see what was removed/added
#
# Usage:
#   ./scripts/validate_detector_change.sh <detector_id>
#   ./scripts/validate_detector_change.sh reentrancy
#   ./scripts/validate_detector_change.sh --compare   # Run after changes

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEMP_DIR="/tmp/soliditydefend_validation"
TEST_CONTRACTS_DIR="tests/contracts"
GROUND_TRUTH_FILE="tests/validation/ground_truth.json"

# Ensure we're in the project root
if [ ! -f "Cargo.toml" ] || [ ! -d "crates" ]; then
    echo -e "${RED}Error: Please run this script from the SolidityDefend project root${NC}"
    exit 1
fi

# Create temp directory
mkdir -p "$TEMP_DIR"

# Function to build the project
build_project() {
    echo -e "${BLUE}Building SolidityDefend...${NC}"
    cargo build --release --quiet
    echo -e "${GREEN}Build complete${NC}"
}

# Function to get findings for a specific detector
get_detector_findings() {
    local detector=$1
    local output_file=$2

    echo -e "${BLUE}Getting findings for detector: ${detector}${NC}"

    # Run analysis on test contracts and filter by detector
    find "$TEST_CONTRACTS_DIR" -name "*.sol" -type f | while read -r contract; do
        ./target/release/soliditydefend "$contract" --format json 2>/dev/null || true
    done | jq -s 'map(.findings // []) | flatten | map(select(.detector_id == "'"$detector"'"))' > "$output_file"

    local count=$(jq 'length' "$output_file")
    echo -e "${GREEN}Found ${count} findings for ${detector}${NC}"
}

# Function to run full validation
run_validation() {
    echo -e "${BLUE}Running validation against ground truth...${NC}"
    ./target/release/soliditydefend --validate --ground-truth "$GROUND_TRUTH_FILE"
}

# Function to get baseline before changes
get_baseline() {
    local detector=$1

    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  BASELINE CAPTURE: ${detector}${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo ""

    build_project

    # Save current findings
    local baseline_file="$TEMP_DIR/baseline_${detector}.json"
    get_detector_findings "$detector" "$baseline_file"

    # Show sample of findings
    echo ""
    echo -e "${BLUE}Sample findings (first 10):${NC}"
    jq -r '.[0:10][] | "  \(.primary_location.file):\(.primary_location.line) - \(.message[0:80])..."' "$baseline_file" 2>/dev/null || echo "  No findings"

    # Run validation to get current precision/recall
    echo ""
    echo -e "${BLUE}Current validation metrics:${NC}"
    run_validation 2>&1 | grep -E "(Precision|Recall|F1 Score|True Positives|False)" || true

    echo ""
    echo -e "${GREEN}Baseline saved to: ${baseline_file}${NC}"
    echo ""
    echo -e "${YELLOW}Now make your detector changes, then run:${NC}"
    echo -e "${YELLOW}  ./scripts/validate_detector_change.sh --compare ${detector}${NC}"
}

# Function to compare after changes
compare_changes() {
    local detector=$1
    local baseline_file="$TEMP_DIR/baseline_${detector}.json"

    if [ ! -f "$baseline_file" ]; then
        echo -e "${RED}Error: No baseline found for ${detector}${NC}"
        echo -e "${RED}Run the baseline first: ./scripts/validate_detector_change.sh ${detector}${NC}"
        exit 1
    fi

    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  COMPARING CHANGES: ${detector}${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo ""

    build_project

    # Get new findings
    local after_file="$TEMP_DIR/after_${detector}.json"
    get_detector_findings "$detector" "$after_file"

    # Compare findings
    local before_count=$(jq 'length' "$baseline_file")
    local after_count=$(jq 'length' "$after_file")

    echo ""
    echo -e "${BLUE}Finding counts:${NC}"
    echo "  Before: $before_count"
    echo "  After:  $after_count"
    echo "  Change: $(( after_count - before_count ))"

    # Find removed findings (potential true positives lost)
    local removed_file="$TEMP_DIR/removed_${detector}.json"
    jq -s '(.[0] | map({key: "\(.primary_location.file):\(.primary_location.line)", value: .}) | from_entries) as $before |
           (.[1] | map({key: "\(.primary_location.file):\(.primary_location.line)", value: .}) | from_entries) as $after |
           [$before | to_entries[] | select(.key | in($after) | not) | .value]' "$baseline_file" "$after_file" > "$removed_file"

    local removed_count=$(jq 'length' "$removed_file")

    if [ "$removed_count" -gt 0 ]; then
        echo ""
        echo -e "${RED}REMOVED FINDINGS (verify these are false positives):${NC}"
        jq -r '.[] | "  \(.primary_location.file):\(.primary_location.line)"' "$removed_file"
        echo ""
        echo -e "${YELLOW}Review these carefully - if any are true vulnerabilities, the change introduces a regression!${NC}"
    else
        echo ""
        echo -e "${GREEN}No findings were removed${NC}"
    fi

    # Find added findings
    local added_file="$TEMP_DIR/added_${detector}.json"
    jq -s '(.[0] | map({key: "\(.primary_location.file):\(.primary_location.line)", value: .}) | from_entries) as $before |
           (.[1] | map({key: "\(.primary_location.file):\(.primary_location.line)", value: .}) | from_entries) as $after |
           [$after | to_entries[] | select(.key | in($before) | not) | .value]' "$baseline_file" "$after_file" > "$added_file"

    local added_count=$(jq 'length' "$added_file")

    if [ "$added_count" -gt 0 ]; then
        echo ""
        echo -e "${BLUE}ADDED FINDINGS:${NC}"
        jq -r '.[] | "  \(.primary_location.file):\(.primary_location.line)"' "$added_file"
    fi

    # Run validation to get new precision/recall
    echo ""
    echo -e "${BLUE}New validation metrics:${NC}"
    run_validation 2>&1 | grep -E "(Precision|Recall|F1 Score|True Positives|False)" || true

    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  SUMMARY${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  Detector:        $detector"
    echo "  Findings before: $before_count"
    echo "  Findings after:  $after_count"
    echo "  Removed:         $removed_count"
    echo "  Added:           $added_count"
    echo ""

    if [ "$removed_count" -gt 0 ]; then
        echo -e "${YELLOW}WARNING: ${removed_count} findings were removed. Please verify they are all false positives.${NC}"
        echo ""
        echo -e "${BLUE}To review removed findings:${NC}"
        echo "  cat $removed_file | jq"
    fi
}

# Function to clean up temp files
cleanup() {
    echo -e "${BLUE}Cleaning up temp files...${NC}"
    rm -rf "$TEMP_DIR"
    echo -e "${GREEN}Done${NC}"
}

# Main logic
case "${1:-}" in
    --compare)
        if [ -z "${2:-}" ]; then
            echo -e "${RED}Error: Please specify detector ID${NC}"
            echo "Usage: $0 --compare <detector_id>"
            exit 1
        fi
        compare_changes "$2"
        ;;
    --cleanup)
        cleanup
        ;;
    --validate)
        build_project
        run_validation
        ;;
    --help|-h)
        echo "Detector Change Validation Script"
        echo ""
        echo "Usage:"
        echo "  $0 <detector_id>           Get baseline for detector before changes"
        echo "  $0 --compare <detector_id>  Compare findings after changes"
        echo "  $0 --validate              Run full validation against ground truth"
        echo "  $0 --cleanup               Remove temp files"
        echo "  $0 --help                  Show this help"
        echo ""
        echo "Workflow:"
        echo "  1. Run: $0 reentrancy        (before making changes)"
        echo "  2. Make your detector changes"
        echo "  3. Run: $0 --compare reentrancy"
        echo "  4. Review removed findings to ensure they're false positives"
        ;;
    "")
        echo -e "${RED}Error: Please specify a detector ID or command${NC}"
        echo "Usage: $0 <detector_id> | --compare <detector_id> | --validate | --cleanup | --help"
        exit 1
        ;;
    *)
        get_baseline "$1"
        ;;
esac
