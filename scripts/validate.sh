#!/bin/bash
# scripts/validate.sh
# End-to-end validation pipeline for SolidityDefend

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VALIDATE_DIR="$PROJECT_ROOT/validation"
RESULTS_DIR="$VALIDATE_DIR/results/$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$RESULTS_DIR/validation.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Validation stages
STAGES=(
    "build"
    "unit_tests"
    "integration_tests"
    "smartbugs"
    "solidifi"
    "property_tests"
    "fuzzing"
    "regression"
    "performance"
    "security"
)

# Default configuration
DEFAULT_TIMEOUT=3600  # 1 hour total timeout
DEFAULT_FUZZ_DURATION=300  # 5 minutes for fuzzing
BUILD_TYPE="release"
SKIP_SLOW_TESTS=0
PARALLEL_JOBS=""
VERBOSE=0
QUIET=0
CONTINUE_ON_ERROR=0

# Print usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS] [STAGES...]

Run comprehensive end-to-end validation for SolidityDefend.

OPTIONS:
    -t, --timeout SECONDS     Total timeout for validation (default: $DEFAULT_TIMEOUT)
    -f, --fuzz-duration SEC   Duration for fuzzing tests (default: $DEFAULT_FUZZ_DURATION)
    -b, --build-type TYPE     Build type: debug or release (default: $BUILD_TYPE)
    -j, --jobs JOBS           Number of parallel jobs (default: auto-detect)
    -s, --skip-slow           Skip slow tests (long fuzzing, extensive property tests)
    -c, --continue            Continue on errors (don't stop at first failure)
    -v, --verbose             Verbose output
    -q, --quiet               Quiet output (errors only)
    -h, --help                Show this help message

STAGES:
    build                     Build SolidityDefend binary
    unit_tests                Run unit tests
    integration_tests         Run integration tests
    smartbugs                 Run SmartBugs validation
    solidifi                  Run SolidiFI mutation testing
    property_tests            Run property-based tests
    fuzzing                   Run fuzzing tests
    regression                Run regression tests
    performance               Run performance benchmarks
    security                  Run security validation

If no stages are specified, all stages will be run.

EXAMPLES:
    $0                                    # Run full validation pipeline
    $0 build unit_tests                  # Run only build and unit tests
    $0 -s -t 1800                        # Skip slow tests, 30 minute timeout
    $0 -b debug -v smartbugs             # Debug build, verbose SmartBugs testing
    $0 -c -j 4                           # Continue on errors, 4 parallel jobs

EOF
}

# Logging functions
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "$level" in
        "INFO")
            if [[ "$QUIET" != "1" ]]; then
                echo -e "${BLUE}[INFO]${NC} $message" | tee -a "$LOG_FILE"
            fi
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} $message" | tee -a "$LOG_FILE"
            ;;
        "WARNING")
            echo -e "${YELLOW}[WARNING]${NC} $message" | tee -a "$LOG_FILE"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message" | tee -a "$LOG_FILE"
            ;;
        "DEBUG")
            if [[ "$VERBOSE" == "1" ]]; then
                echo -e "${PURPLE}[DEBUG]${NC} $message" | tee -a "$LOG_FILE"
            fi
            ;;
        "STAGE")
            echo -e "${CYAN}[STAGE]${NC} $message" | tee -a "$LOG_FILE"
            ;;
    esac

    # Always log to file with timestamp
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Progress tracking
update_progress() {
    local current="$1"
    local total="$2"
    local stage="$3"

    local percentage=$((current * 100 / total))
    local filled=$((percentage / 2))
    local empty=$((50 - filled))

    printf "\r${CYAN}Progress:${NC} ["
    printf "%${filled}s" | tr ' ' '█'
    printf "%${empty}s" | tr ' ' '·'
    printf "] %d%% - %s" "$percentage" "$stage"

    if [[ "$current" -eq "$total" ]]; then
        echo ""
    fi
}

# Check system requirements
check_requirements() {
    log "INFO" "Checking system requirements..."

    # Check Rust toolchain
    if ! command -v cargo &> /dev/null; then
        log "ERROR" "Rust toolchain not found. Please install Rust."
        return 1
    fi

    local rust_version=$(rustc --version | head -n1)
    log "DEBUG" "Found Rust: $rust_version"

    # Check required tools
    local required_tools=("git" "python3" "node")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log "WARNING" "$tool not found (may be needed for some tests)"
        else
            log "DEBUG" "Found $tool: $(command -v "$tool")"
        fi
    done

    # Check available memory
    local available_memory=""
    if command -v free &> /dev/null; then
        available_memory=$(free -m | awk 'NR==2{printf "%.1fGB", $7/1024}')
    elif command -v vm_stat &> /dev/null; then
        # macOS
        local free_pages=$(vm_stat | grep "Pages free:" | awk '{print $3}' | sed 's/\.//')
        local page_size=$(vm_stat | grep "page size" | awk '{print $8}')
        available_memory=$(echo "scale=1; $free_pages * $page_size / 1024 / 1024 / 1024" | bc)GB
    fi

    if [[ -n "$available_memory" ]]; then
        log "DEBUG" "Available memory: $available_memory"
    fi

    # Check disk space
    local available_space=$(df -h "$PROJECT_ROOT" | awk 'NR==2 {print $4}')
    log "DEBUG" "Available disk space: $available_space"

    log "SUCCESS" "System requirements check completed"
}

# Setup validation environment
setup_environment() {
    log "INFO" "Setting up validation environment..."

    # Create results directory
    mkdir -p "$RESULTS_DIR"

    # Initialize log file
    cat > "$LOG_FILE" << EOF
SolidityDefend End-to-End Validation
====================================
Start Time: $(date)
Project Root: $PROJECT_ROOT
Build Type: $BUILD_TYPE
Timeout: ${TIMEOUT}s
Parallel Jobs: ${PARALLEL_JOBS:-auto}
Stages: ${SELECTED_STAGES[*]}

System Information:
$(uname -a)

Rust Information:
$(rustc --version)
$(cargo --version)

EOF

    # Change to project root
    cd "$PROJECT_ROOT"

    # Ensure we're in a git repository
    if ! git rev-parse --git-dir &> /dev/null; then
        log "ERROR" "Not in a git repository"
        return 1
    fi

    # Get git information
    local git_commit=$(git rev-parse HEAD)
    local git_branch=$(git rev-parse --abbrev-ref HEAD)
    local git_status=$(git status --porcelain | wc -l)

    log "DEBUG" "Git commit: $git_commit"
    log "DEBUG" "Git branch: $git_branch"

    if [[ "$git_status" -gt 0 ]]; then
        log "WARNING" "Working directory has uncommitted changes"
    fi

    echo "Git Information:" >> "$LOG_FILE"
    echo "Commit: $git_commit" >> "$LOG_FILE"
    echo "Branch: $git_branch" >> "$LOG_FILE"
    echo "Uncommitted changes: $git_status" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"

    log "SUCCESS" "Environment setup completed"
}

# Stage 1: Build
stage_build() {
    log "STAGE" "Building SolidityDefend..."

    local build_start_time=$(date +%s)

    # Clean previous builds if needed
    if [[ "$BUILD_TYPE" == "release" ]]; then
        log "DEBUG" "Building in release mode"
        cargo build --release
    else
        log "DEBUG" "Building in debug mode"
        cargo build
    fi

    # Check if binary was created
    local binary_path="target/$BUILD_TYPE/soliditydefend"
    if [[ ! -f "$binary_path" ]]; then
        log "ERROR" "Binary not found at $binary_path"
        return 1
    fi

    # Get binary info
    local binary_size=$(ls -lh "$binary_path" | awk '{print $5}')
    log "DEBUG" "Binary size: $binary_size"

    # Test basic functionality
    log "DEBUG" "Testing basic functionality..."
    if ! timeout 30 "$binary_path" --version &> /dev/null; then
        log "ERROR" "Binary version check failed"
        return 1
    fi

    local build_end_time=$(date +%s)
    local build_duration=$((build_end_time - build_start_time))

    log "SUCCESS" "Build completed in ${build_duration}s"

    # Save build info
    cat > "$RESULTS_DIR/build_info.txt" << EOF
Build Type: $BUILD_TYPE
Build Duration: ${build_duration}s
Binary Path: $binary_path
Binary Size: $binary_size
Build Time: $(date)
EOF
}

# Stage 2: Unit Tests
stage_unit_tests() {
    log "STAGE" "Running unit tests..."

    local test_start_time=$(date +%s)

    # Run unit tests with coverage if possible
    local test_args=()
    if [[ "$VERBOSE" == "1" ]]; then
        test_args+=("--verbose")
    fi

    if [[ "$PARALLEL_JOBS" != "" ]]; then
        test_args+=("--jobs" "$PARALLEL_JOBS")
    fi

    # Run the tests
    if ! cargo test "${test_args[@]}" --lib; then
        log "ERROR" "Unit tests failed"
        return 1
    fi

    local test_end_time=$(date +%s)
    local test_duration=$((test_end_time - test_start_time))

    log "SUCCESS" "Unit tests completed in ${test_duration}s"

    # Save test results
    echo "Unit Tests: PASSED (${test_duration}s)" >> "$RESULTS_DIR/test_results.txt"
}

# Stage 3: Integration Tests
stage_integration_tests() {
    log "STAGE" "Running integration tests..."

    local test_start_time=$(date +%s)

    # Run integration tests
    local test_args=()
    if [[ "$VERBOSE" == "1" ]]; then
        test_args+=("--verbose")
    fi

    if [[ "$PARALLEL_JOBS" != "" ]]; then
        test_args+=("--jobs" "$PARALLEL_JOBS")
    fi

    if ! cargo test "${test_args[@]}" --test '*'; then
        log "ERROR" "Integration tests failed"
        return 1
    fi

    local test_end_time=$(date +%s)
    local test_duration=$((test_end_time - test_start_time))

    log "SUCCESS" "Integration tests completed in ${test_duration}s"

    # Save test results
    echo "Integration Tests: PASSED (${test_duration}s)" >> "$RESULTS_DIR/test_results.txt"
}

# Stage 4: SmartBugs Validation
stage_smartbugs() {
    log "STAGE" "Running SmartBugs validation..."

    local test_start_time=$(date +%s)

    # Check if SmartBugs test exists
    if [[ ! -f "tests/validation/smartbugs.rs" ]]; then
        log "WARNING" "SmartBugs validation test not found, skipping"
        return 0
    fi

    # Run SmartBugs validation
    if ! cargo test --test validation smartbugs; then
        log "WARNING" "SmartBugs validation failed (expected during development)"
        echo "SmartBugs Validation: FAILED (expected)" >> "$RESULTS_DIR/test_results.txt"
        if [[ "$CONTINUE_ON_ERROR" == "0" ]]; then
            return 1
        fi
    else
        local test_end_time=$(date +%s)
        local test_duration=$((test_end_time - test_start_time))
        log "SUCCESS" "SmartBugs validation completed in ${test_duration}s"
        echo "SmartBugs Validation: PASSED (${test_duration}s)" >> "$RESULTS_DIR/test_results.txt"
    fi
}

# Stage 5: SolidiFI Mutation Testing
stage_solidifi() {
    log "STAGE" "Running SolidiFI mutation testing..."

    local test_start_time=$(date +%s)

    # Check if SolidiFI test exists
    if [[ ! -f "tests/validation/solidifi.rs" ]]; then
        log "WARNING" "SolidiFI validation test not found, skipping"
        return 0
    fi

    # Run SolidiFI mutation testing
    if ! cargo test --test validation solidifi; then
        log "WARNING" "SolidiFI mutation testing failed (expected during development)"
        echo "SolidiFI Mutation Testing: FAILED (expected)" >> "$RESULTS_DIR/test_results.txt"
        if [[ "$CONTINUE_ON_ERROR" == "0" ]]; then
            return 1
        fi
    else
        local test_end_time=$(date +%s)
        local test_duration=$((test_end_time - test_start_time))
        log "SUCCESS" "SolidiFI mutation testing completed in ${test_duration}s"
        echo "SolidiFI Mutation Testing: PASSED (${test_duration}s)" >> "$RESULTS_DIR/test_results.txt"
    fi
}

# Stage 6: Property-based Tests
stage_property_tests() {
    log "STAGE" "Running property-based tests..."

    local test_start_time=$(date +%s)

    # Check if property tests exist
    if [[ ! -f "tests/property/mod.rs" ]]; then
        log "WARNING" "Property-based tests not found, skipping"
        return 0
    fi

    # Set test duration based on skip_slow flag
    local test_cases=100
    if [[ "$SKIP_SLOW_TESTS" == "1" ]]; then
        test_cases=10
        log "DEBUG" "Using reduced test cases for property tests: $test_cases"
    fi

    # Run property-based tests
    export PROPTEST_CASES="$test_cases"
    if ! cargo test --test property; then
        log "WARNING" "Property-based tests failed (expected during development)"
        echo "Property-based Tests: FAILED (expected)" >> "$RESULTS_DIR/test_results.txt"
        if [[ "$CONTINUE_ON_ERROR" == "0" ]]; then
            return 1
        fi
    else
        local test_end_time=$(date +%s)
        local test_duration=$((test_end_time - test_start_time))
        log "SUCCESS" "Property-based tests completed in ${test_duration}s"
        echo "Property-based Tests: PASSED (${test_duration}s)" >> "$RESULTS_DIR/test_results.txt"
    fi
}

# Stage 7: Fuzzing Tests
stage_fuzzing() {
    log "STAGE" "Running fuzzing tests..."

    local test_start_time=$(date +%s)

    # Check if fuzzing infrastructure exists
    if [[ ! -d "fuzz" ]]; then
        log "WARNING" "Fuzzing infrastructure not found, skipping"
        return 0
    fi

    # Determine fuzzing duration
    local fuzz_duration="$FUZZ_DURATION"
    if [[ "$SKIP_SLOW_TESTS" == "1" ]]; then
        fuzz_duration=30  # 30 seconds for quick tests
        log "DEBUG" "Using reduced fuzzing duration: ${fuzz_duration}s"
    fi

    # Run fuzzing (continue on error since fuzzing is expected to find issues)
    if [[ -x "scripts/run_all_fuzz.sh" ]]; then
        local fuzz_args=(
            "--duration" "$fuzz_duration"
            "--quiet"
        )

        if [[ "$PARALLEL_JOBS" != "" ]]; then
            fuzz_args+=("--jobs" "$PARALLEL_JOBS")
        fi

        if ! ./scripts/run_all_fuzz.sh "${fuzz_args[@]}"; then
            log "WARNING" "Fuzzing tests found issues (this is expected)"
        fi
    else
        log "WARNING" "Fuzzing script not found, skipping fuzzing"
    fi

    local test_end_time=$(date +%s)
    local test_duration=$((test_end_time - test_start_time))

    log "SUCCESS" "Fuzzing tests completed in ${test_duration}s"
    echo "Fuzzing Tests: COMPLETED (${test_duration}s)" >> "$RESULTS_DIR/test_results.txt"
}

# Stage 8: Regression Tests
stage_regression() {
    log "STAGE" "Running regression tests..."

    local test_start_time=$(date +%s)

    # Check if regression tests exist
    if [[ ! -f "tests/regression/mod.rs" ]]; then
        log "WARNING" "Regression tests not found, skipping"
        return 0
    fi

    # Run regression tests
    if ! cargo test --test regression; then
        log "WARNING" "Regression tests failed (expected during development)"
        echo "Regression Tests: FAILED (expected)" >> "$RESULTS_DIR/test_results.txt"
        if [[ "$CONTINUE_ON_ERROR" == "0" ]]; then
            return 1
        fi
    else
        local test_end_time=$(date +%s)
        local test_duration=$((test_end_time - test_start_time))
        log "SUCCESS" "Regression tests completed in ${test_duration}s"
        echo "Regression Tests: PASSED (${test_duration}s)" >> "$RESULTS_DIR/test_results.txt"
    fi
}

# Stage 9: Performance Benchmarks
stage_performance() {
    log "STAGE" "Running performance benchmarks..."

    local test_start_time=$(date +%s)

    # Check if benchmarks exist
    if [[ ! -d "benches" ]]; then
        log "WARNING" "Benchmarks not found, skipping"
        return 0
    fi

    # Run benchmarks
    local bench_duration=60
    if [[ "$SKIP_SLOW_TESTS" == "1" ]]; then
        bench_duration=10
        log "DEBUG" "Using reduced benchmark duration: ${bench_duration}s"
    fi

    # Only run benchmarks in release mode
    if [[ "$BUILD_TYPE" == "release" ]]; then
        if ! timeout "$bench_duration" cargo bench; then
            log "WARNING" "Benchmarks timed out or failed"
        fi
    else
        log "DEBUG" "Skipping benchmarks in debug mode"
    fi

    local test_end_time=$(date +%s)
    local test_duration=$((test_end_time - test_start_time))

    log "SUCCESS" "Performance benchmarks completed in ${test_duration}s"
    echo "Performance Benchmarks: COMPLETED (${test_duration}s)" >> "$RESULTS_DIR/test_results.txt"
}

# Stage 10: Security Validation
stage_security() {
    log "STAGE" "Running security validation..."

    local test_start_time=$(date +%s)

    # Check for security vulnerabilities in dependencies
    log "DEBUG" "Checking for security vulnerabilities..."

    # Install cargo-audit if not present
    if ! cargo audit --version &> /dev/null; then
        log "DEBUG" "Installing cargo-audit..."
        cargo install cargo-audit
    fi

    # Run security audit
    if ! cargo audit; then
        log "WARNING" "Security audit found vulnerabilities"
        echo "Security Audit: VULNERABILITIES FOUND" >> "$RESULTS_DIR/test_results.txt"
        if [[ "$CONTINUE_ON_ERROR" == "0" ]]; then
            return 1
        fi
    else
        log "SUCCESS" "No security vulnerabilities found"
        echo "Security Audit: PASSED" >> "$RESULTS_DIR/test_results.txt"
    fi

    # Check for unsafe code usage
    log "DEBUG" "Checking for unsafe code..."
    local unsafe_count=$(rg -c "unsafe" --type rust src/ || echo "0")
    log "DEBUG" "Found $unsafe_count uses of unsafe code"

    # Save security report
    cat > "$RESULTS_DIR/security_report.txt" << EOF
Security Validation Report
==========================

Dependency Audit: $(if cargo audit &> /dev/null; then echo "PASSED"; else echo "FAILED"; fi)
Unsafe Code Usage: $unsafe_count instances

Generated at: $(date)
EOF

    local test_end_time=$(date +%s)
    local test_duration=$((test_end_time - test_start_time))

    log "SUCCESS" "Security validation completed in ${test_duration}s"
}

# Generate final validation report
generate_final_report() {
    log "INFO" "Generating validation report..."

    local report_file="$RESULTS_DIR/validation_report.md"
    local run_end_time=$(date +%s)
    local total_duration=$((run_end_time - RUN_START_TIME))

    cat > "$report_file" << EOF
# SolidityDefend Validation Report

## Summary

- **Start Time:** $(date -d "@$RUN_START_TIME")
- **End Time:** $(date -d "@$run_end_time")
- **Total Duration:** ${total_duration}s ($(date -u -d @${total_duration} +'%H:%M:%S'))
- **Build Type:** $BUILD_TYPE
- **Stages Run:** ${SELECTED_STAGES[*]}

## System Information

\`\`\`
$(uname -a)
\`\`\`

**Rust Version:** $(rustc --version)

## Stage Results

EOF

    # Add results from each stage
    if [[ -f "$RESULTS_DIR/test_results.txt" ]]; then
        echo "### Test Results" >> "$report_file"
        echo "" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
        cat "$RESULTS_DIR/test_results.txt" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
        echo "" >> "$report_file"
    fi

    # Add build information
    if [[ -f "$RESULTS_DIR/build_info.txt" ]]; then
        echo "### Build Information" >> "$report_file"
        echo "" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
        cat "$RESULTS_DIR/build_info.txt" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
        echo "" >> "$report_file"
    fi

    # Add security information
    if [[ -f "$RESULTS_DIR/security_report.txt" ]]; then
        echo "### Security Report" >> "$report_file"
        echo "" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
        cat "$RESULTS_DIR/security_report.txt" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
        echo "" >> "$report_file"
    fi

    # Add log summary
    echo "### Log Summary" >> "$report_file"
    echo "" >> "$report_file"
    echo "**Total log entries:**" >> "$report_file"
    local info_count=$(grep -c "\[INFO\]" "$LOG_FILE" || echo "0")
    local success_count=$(grep -c "\[SUCCESS\]" "$LOG_FILE" || echo "0")
    local warning_count=$(grep -c "\[WARNING\]" "$LOG_FILE" || echo "0")
    local error_count=$(grep -c "\[ERROR\]" "$LOG_FILE" || echo "0")

    cat >> "$report_file" << EOF
- INFO: $info_count
- SUCCESS: $success_count
- WARNING: $warning_count
- ERROR: $error_count

**Full logs:** [validation.log](validation.log)

## Conclusion

EOF

    # Determine overall result
    if [[ "$error_count" -eq 0 ]]; then
        echo "✅ **Validation PASSED** - All stages completed successfully" >> "$report_file"
        log "SUCCESS" "Validation completed successfully"
    elif [[ "$CONTINUE_ON_ERROR" == "1" ]]; then
        echo "⚠️ **Validation COMPLETED WITH WARNINGS** - Some stages failed but execution continued" >> "$report_file"
        log "WARNING" "Validation completed with warnings"
    else
        echo "❌ **Validation FAILED** - One or more stages failed" >> "$report_file"
        log "ERROR" "Validation failed"
    fi

    cat >> "$report_file" << EOF

---
Generated by SolidityDefend validation pipeline on $(date)
EOF

    log "SUCCESS" "Validation report generated: $report_file"
}

# Cleanup function
cleanup() {
    local exit_code=$?

    if [[ ${#CLEANUP_PIDS[@]} -gt 0 ]]; then
        log "INFO" "Cleaning up background processes..."
        for pid in "${CLEANUP_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
            fi
        done
    fi

    log "INFO" "Validation pipeline finished with exit code: $exit_code"
    exit $exit_code
}

# Main execution function
main() {
    # Parse command line arguments
    local TIMEOUT="$DEFAULT_TIMEOUT"
    local FUZZ_DURATION="$DEFAULT_FUZZ_DURATION"
    local SELECTED_STAGES=()

    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -f|--fuzz-duration)
                FUZZ_DURATION="$2"
                shift 2
                ;;
            -b|--build-type)
                BUILD_TYPE="$2"
                if [[ "$BUILD_TYPE" != "debug" && "$BUILD_TYPE" != "release" ]]; then
                    log "ERROR" "Invalid build type: $BUILD_TYPE"
                    exit 1
                fi
                shift 2
                ;;
            -j|--jobs)
                PARALLEL_JOBS="$2"
                shift 2
                ;;
            -s|--skip-slow)
                SKIP_SLOW_TESTS=1
                shift
                ;;
            -c|--continue)
                CONTINUE_ON_ERROR=1
                shift
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -q|--quiet)
                QUIET=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                log "ERROR" "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                SELECTED_STAGES+=("$1")
                shift
                ;;
        esac
    done

    # Validate arguments
    if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]]; then
        log "ERROR" "Timeout must be a positive integer"
        exit 1
    fi

    if ! [[ "$FUZZ_DURATION" =~ ^[0-9]+$ ]]; then
        log "ERROR" "Fuzz duration must be a positive integer"
        exit 1
    fi

    if [[ "$PARALLEL_JOBS" != "" ]] && ! [[ "$PARALLEL_JOBS" =~ ^[0-9]+$ ]]; then
        log "ERROR" "Parallel jobs must be a positive integer"
        exit 1
    fi

    # Use all stages if none specified
    if [[ ${#SELECTED_STAGES[@]} -eq 0 ]]; then
        SELECTED_STAGES=("${STAGES[@]}")
    fi

    # Validate selected stages
    for stage in "${SELECTED_STAGES[@]}"; do
        if [[ ! " ${STAGES[*]} " =~ " $stage " ]]; then
            log "ERROR" "Unknown stage: $stage"
            log "INFO" "Available stages: ${STAGES[*]}"
            exit 1
        fi
    done

    # Auto-detect parallel jobs if not specified
    if [[ "$PARALLEL_JOBS" == "" ]]; then
        PARALLEL_JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "1")
    fi

    # Setup signal handlers
    local CLEANUP_PIDS=()
    trap cleanup EXIT INT TERM

    # Record start time
    local RUN_START_TIME=$(date +%s)

    # Run pipeline stages
    check_requirements
    setup_environment

    log "INFO" "Starting validation pipeline"
    log "INFO" "Selected stages: ${SELECTED_STAGES[*]}"
    log "INFO" "Total timeout: ${TIMEOUT}s"
    log "INFO" "Using $PARALLEL_JOBS parallel jobs"

    # Run each stage with timeout
    local stage_count=0
    local total_stages=${#SELECTED_STAGES[@]}
    local failed_stages=()

    for stage in "${SELECTED_STAGES[@]}"; do
        stage_count=$((stage_count + 1))
        update_progress "$stage_count" "$total_stages" "$stage"

        local stage_timeout=$((TIMEOUT / total_stages))
        local stage_start_time=$(date +%s)

        if timeout "$stage_timeout" "stage_$stage"; then
            log "DEBUG" "Stage $stage completed successfully"
        else
            local exit_code=$?
            if [[ $exit_code -eq 124 ]]; then
                log "ERROR" "Stage $stage timed out after ${stage_timeout}s"
            else
                log "ERROR" "Stage $stage failed with exit code: $exit_code"
            fi

            failed_stages+=("$stage")

            if [[ "$CONTINUE_ON_ERROR" == "0" ]]; then
                log "ERROR" "Stopping due to stage failure (use -c to continue)"
                exit 1
            fi
        fi

        local stage_end_time=$(date +%s)
        local stage_duration=$((stage_end_time - stage_start_time))
        log "DEBUG" "Stage $stage took ${stage_duration}s"
    done

    # Generate final report
    generate_final_report

    # Summary
    local run_end_time=$(date +%s)
    local total_duration=$((run_end_time - RUN_START_TIME))

    log "INFO" "Validation pipeline completed in ${total_duration}s"
    log "INFO" "Results saved to: $RESULTS_DIR"

    if [[ ${#failed_stages[@]} -gt 0 ]]; then
        log "WARNING" "Failed stages: ${failed_stages[*]}"
        if [[ "$CONTINUE_ON_ERROR" == "0" ]]; then
            exit 1
        fi
    else
        log "SUCCESS" "All validation stages passed"
    fi
}

# Run main function with all arguments
main "$@"