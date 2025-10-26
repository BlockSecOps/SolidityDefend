#!/bin/bash
# Comprehensive Detector Validation Script
# Tests all 100 detectors against test contracts and compares with expected results

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY="${PROJECT_ROOT}/target/release/soliditydefend"
TEST_CONTRACTS_DIR="${PROJECT_ROOT}/tests/contracts"
RESULTS_DIR="${PROJECT_ROOT}/test-results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${RESULTS_DIR}/validation_${TIMESTAMP}.log"
SUMMARY_FILE="${RESULTS_DIR}/summary_${TIMESTAMP}.txt"
JSON_RESULTS="${RESULTS_DIR}/results_${TIMESTAMP}.json"

# Create results directory
mkdir -p "${RESULTS_DIR}"

# Initialize counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
WARNINGS=0

# Logging functions
log() {
    echo -e "${1}" | tee -a "${LOG_FILE}"
}

log_header() {
    log "\n${BLUE}========================================${NC}"
    log "${BLUE}${1}${NC}"
    log "${BLUE}========================================${NC}\n"
}

log_success() {
    log "${GREEN}✓ ${1}${NC}"
}

log_error() {
    log "${RED}✗ ${1}${NC}"
}

log_warning() {
    log "${YELLOW}⚠ ${1}${NC}"
}

log_info() {
    log "${NC}  ${1}${NC}"
}

# Check if binary exists
check_binary() {
    log_header "Pre-flight Checks"

    if [ ! -f "${BINARY}" ]; then
        log_warning "Binary not found at ${BINARY}"
        log_info "Building release binary..."
        cd "${PROJECT_ROOT}"
        if timeout 120 cargo build --release --bin soliditydefend >> "${LOG_FILE}" 2>&1; then
            log_success "Binary built successfully"
        else
            log_error "Failed to build binary"
            exit 1
        fi
    else
        log_success "Binary found at ${BINARY}"
    fi

    # Verify binary works (note: --version exits with code 1 but still works)
    VERSION=$("${BINARY}" --version 2>&1 || true)
    if [ -n "${VERSION}" ]; then
        log_success "Binary version: ${VERSION}"
    else
        log_error "Binary is not executable or failed to run"
        exit 1
    fi
}

# List all detectors
list_detectors() {
    log_header "Registered Detectors"

    DETECTOR_COUNT=$("${BINARY}" --list-detectors 2>/dev/null | grep "^  " | wc -l | tr -d ' ')
    log_info "Total detectors registered: ${DETECTOR_COUNT}"

    if [ "${DETECTOR_COUNT}" -ne 100 ]; then
        log_warning "Expected 100 detectors but found ${DETECTOR_COUNT}"
    else
        log_success "All 100 detectors are registered"
    fi

    # Save detector list
    "${BINARY}" --list-detectors > "${RESULTS_DIR}/detector_list_${TIMESTAMP}.txt" 2>&1
    log_info "Detector list saved to: detector_list_${TIMESTAMP}.txt"
}

# Find all test contracts
find_test_contracts() {
    log_header "Discovering Test Contracts"

    # Find all .sol files
    CONTRACTS=$(find "${TEST_CONTRACTS_DIR}" -name "*.sol" -type f | sort)
    CONTRACT_COUNT=$(echo "${CONTRACTS}" | wc -l | tr -d ' ')

    log_info "Found ${CONTRACT_COUNT} test contracts"

    # Categorize contracts
    VULNERABLE_COUNT=$(echo "${CONTRACTS}" | grep -i "vulnerable" | wc -l | tr -d ' ')
    CLEAN_COUNT=$(echo "${CONTRACTS}" | grep -i -E "clean|secure" | wc -l | tr -d ' ')
    OTHER_COUNT=$((CONTRACT_COUNT - VULNERABLE_COUNT - CLEAN_COUNT))

    log_info "  - Vulnerable contracts: ${VULNERABLE_COUNT}"
    log_info "  - Clean/Secure contracts: ${CLEAN_COUNT}"
    log_info "  - Other test contracts: ${OTHER_COUNT}"

    echo "${CONTRACTS}"
}

# Test a single contract
test_contract() {
    local contract_path="$1"
    local contract_name=$(basename "${contract_path}")
    local contract_dir=$(dirname "${contract_path}")
    local relative_path="${contract_path#${TEST_CONTRACTS_DIR}/}"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    log_info "Testing: ${relative_path}"

    # Run detector on contract
    local output_file="${RESULTS_DIR}/individual/${TIMESTAMP}/${relative_path%.sol}.json"
    mkdir -p "$(dirname "${output_file}")"

    # Run with JSON format for parsing (ignore exit code - binary may return non-zero with findings)
    "${BINARY}" "${contract_path}" --format json > "${output_file}" 2>&1 || true

    # Check if valid JSON output was generated
    if [ -s "${output_file}" ] && grep -q '"version"' "${output_file}" 2>/dev/null; then
        # Count total findings
        local total_findings=$(grep -o '"detector_id"' "${output_file}" 2>/dev/null | wc -l | tr -d ' ')

        # Count by severity
        local critical_count=$(grep '"severity":"critical"' "${output_file}" 2>/dev/null | wc -l | tr -d ' ')
        local high_count=$(grep '"severity":"high"' "${output_file}" 2>/dev/null | wc -l | tr -d ' ')
        local medium_count=$(grep '"severity":"medium"' "${output_file}" 2>/dev/null | wc -l | tr -d ' ')
        local low_count=$(grep '"severity":"low"' "${output_file}" 2>/dev/null | wc -l | tr -d ' ')

        # Determine expected behavior based on filename
        if echo "${contract_name}" | grep -qi "vulnerable"; then
            if [ "${total_findings}" -gt 0 ]; then
                log_success "  ${contract_name}: ${total_findings} findings (C:${critical_count} H:${high_count} M:${medium_count} L:${low_count})"
                PASSED_TESTS=$((PASSED_TESTS + 1))
            else
                log_error "  ${contract_name}: Expected findings but found none"
                FAILED_TESTS=$((FAILED_TESTS + 1))
            fi
        elif echo "${contract_name}" | grep -qi -E "clean|secure"; then
            if [ "${critical_count}" -eq 0 ] && [ "${high_count}" -eq 0 ]; then
                log_success "  ${contract_name}: Clean (${total_findings} total, C:${critical_count} H:${high_count} M:${medium_count} L:${low_count})"
                PASSED_TESTS=$((PASSED_TESTS + 1))
            else
                log_warning "  ${contract_name}: Has ${critical_count} critical + ${high_count} high severity findings"
                FAILED_TESTS=$((FAILED_TESTS + 1))
            fi
        else
            # For other contracts, just record the findings
            log_info "  ${contract_name}: ${total_findings} findings (C:${critical_count} H:${high_count} M:${medium_count} L:${low_count})"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        fi
    else
        log_error "  ${contract_name}: Failed to generate valid JSON output"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Test all contracts
test_all_contracts() {
    log_header "Running Detector Tests"

    CONTRACTS=$(find_test_contracts)

    while IFS= read -r contract; do
        test_contract "${contract}"
    done <<< "${CONTRACTS}"
}

# Test specific detector categories
test_detector_categories() {
    log_header "Testing Detector Categories"

    # Phase 13: Cross-Chain
    log_info "Phase 13: Cross-Chain Bridge Security"
    if find "${TEST_CONTRACTS_DIR}/cross_chain" -name "*.sol" 2>/dev/null | head -1 | grep -q .; then
        PHASE13_CONTRACTS=$(find "${TEST_CONTRACTS_DIR}/cross_chain" -name "*.sol" | wc -l | tr -d ' ')
        log_info "  Found ${PHASE13_CONTRACTS} cross-chain test contracts"
    fi

    # Phase 16: ERC-4626 Vaults
    log_info "Phase 16: ERC-4626 Vault Security"
    if find "${TEST_CONTRACTS_DIR}/erc4626_vaults" -name "*.sol" 2>/dev/null | head -1 | grep -q .; then
        PHASE16_CONTRACTS=$(find "${TEST_CONTRACTS_DIR}/erc4626_vaults" -name "*.sol" | wc -l | tr -d ' ')
        log_info "  Found ${PHASE16_CONTRACTS} vault test contracts"
    fi

    # 2025 Vulnerabilities
    log_info "2025 Complex Vulnerability Scenarios"
    if find "${TEST_CONTRACTS_DIR}/complex_scenarios/2025_vulnerabilities" -name "*.sol" 2>/dev/null | head -1 | grep -q .; then
        COMPLEX_CONTRACTS=$(find "${TEST_CONTRACTS_DIR}/complex_scenarios/2025_vulnerabilities" -name "*.sol" | wc -l | tr -d ' ')
        log_info "  Found ${COMPLEX_CONTRACTS} complex scenario contracts"
    fi
}

# Generate summary report
generate_summary() {
    log_header "Test Summary"

    local pass_rate=0
    if [ "${TOTAL_TESTS}" -gt 0 ]; then
        pass_rate=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    fi

    {
        echo "SolidityDefend Detector Validation Report"
        echo "=========================================="
        echo "Timestamp: $(date)"
        echo "Version: $("${BINARY}" --version)"
        echo ""
        echo "Test Results:"
        echo "  Total Tests:    ${TOTAL_TESTS}"
        echo "  Passed:         ${PASSED_TESTS}"
        echo "  Failed:         ${FAILED_TESTS}"
        echo "  Warnings:       ${WARNINGS}"
        echo "  Pass Rate:      ${pass_rate}%"
        echo ""
        echo "Detector Status:"
        echo "  Registered:     ${DETECTOR_COUNT}/100"
        echo ""
        echo "Test Coverage:"
        echo "  Total Contracts:      ${CONTRACT_COUNT}"
        echo "  Vulnerable Contracts: ${VULNERABLE_COUNT}"
        echo "  Clean Contracts:      ${CLEAN_COUNT}"
        echo "  Other Contracts:      ${OTHER_COUNT}"
        echo ""
        echo "Result Files:"
        echo "  Full Log:       ${LOG_FILE}"
        echo "  Summary:        ${SUMMARY_FILE}"
        echo "  JSON Results:   ${JSON_RESULTS}"
        echo ""
    } | tee "${SUMMARY_FILE}"

    if [ "${FAILED_TESTS}" -eq 0 ]; then
        log_success "All tests passed! ✓"
    else
        log_error "${FAILED_TESTS} test(s) failed"
    fi
}

# Main execution
main() {
    log_header "SolidityDefend Detector Validation"
    log_info "Started at: $(date)"
    log_info "Log file: ${LOG_FILE}"

    check_binary
    list_detectors
    test_detector_categories
    test_all_contracts
    generate_summary

    log_header "Validation Complete"
    log_info "Full results available in: ${RESULTS_DIR}"

    # Exit with appropriate code
    if [ "${FAILED_TESTS}" -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main "$@"
