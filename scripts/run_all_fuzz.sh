#!/bin/bash
# scripts/run_all_fuzz.sh
# Comprehensive fuzzing script for SolidityDefend

set -euo pipefail

# Configuration
DEFAULT_DURATION=300  # 5 minutes per target
DEFAULT_MAX_LEN=10000
DEFAULT_RSS_LIMIT=2048  # 2GB
FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../fuzz" && pwd)"
RESULTS_DIR="${FUZZ_DIR}/results/$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${RESULTS_DIR}/fuzz_run.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fuzzing targets
TARGETS=(
    "fuzz_parser"
    "fuzz_analyzer"
    "fuzz_detectors"
    "fuzz_solidity_generator"
    "fuzz_sarif_output"
)

# Print usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Run comprehensive fuzzing tests for SolidityDefend.

OPTIONS:
    -d, --duration SECONDS    Duration to run each target (default: $DEFAULT_DURATION)
    -t, --targets TARGET,...  Comma-separated list of targets to run (default: all)
    -e, --engine ENGINE       Fuzzing engine: libfuzzer or honggfuzz (default: libfuzzer)
    -j, --jobs JOBS           Number of parallel jobs (default: auto-detect)
    -m, --max-len BYTES       Maximum input length (default: $DEFAULT_MAX_LEN)
    -r, --rss-limit MB        RSS memory limit in MB (default: $DEFAULT_RSS_LIMIT)
    -c, --continue            Continue from previous run
    -v, --verbose             Verbose output
    -q, --quiet               Quiet output (errors only)
    -h, --help                Show this help message

EXAMPLES:
    $0                                    # Run all targets for 5 minutes each
    $0 -d 3600 -t fuzz_parser           # Run parser fuzzing for 1 hour
    $0 -e honggfuzz -j 4                 # Use honggfuzz with 4 jobs
    $0 -v -d 1800                        # Verbose mode, 30 minutes per target

TARGETS:
    fuzz_parser               Test Solidity parser robustness
    fuzz_analyzer             Test analysis engine consistency
    fuzz_detectors            Test individual detector implementations
    fuzz_solidity_generator   Test code generation utilities
    fuzz_sarif_output         Test SARIF output generation

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
            echo -e "${BLUE}[INFO]${NC} $message" | tee -a "$LOG_FILE"
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
            if [[ "${VERBOSE:-0}" == "1" ]]; then
                echo -e "${BLUE}[DEBUG]${NC} $message" | tee -a "$LOG_FILE"
            fi
            ;;
    esac

    # Always log to file with timestamp
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Check if required tools are installed
check_dependencies() {
    log "INFO" "Checking dependencies..."

    if ! command -v cargo &> /dev/null; then
        log "ERROR" "cargo is not installed"
        exit 1
    fi

    if [[ "$FUZZING_ENGINE" == "libfuzzer" ]]; then
        if ! cargo fuzz --version &> /dev/null; then
            log "INFO" "Installing cargo-fuzz..."
            cargo install cargo-fuzz
        fi
    elif [[ "$FUZZING_ENGINE" == "honggfuzz" ]]; then
        if ! command -v honggfuzz &> /dev/null; then
            log "ERROR" "honggfuzz is not installed"
            log "INFO" "Install with: cargo install honggfuzz"
            exit 1
        fi
        if ! cargo hfuzz version &> /dev/null; then
            log "INFO" "Installing cargo-hfuzz..."
            cargo install honggfuzz
        fi
    fi

    log "SUCCESS" "All dependencies satisfied"
}

# Setup fuzzing environment
setup_environment() {
    log "INFO" "Setting up fuzzing environment..."

    # Create results directory
    mkdir -p "$RESULTS_DIR"

    # Initialize log file
    cat > "$LOG_FILE" << EOF
SolidityDefend Fuzzing Run
==========================
Start Time: $(date)
Duration per target: ${DURATION}s
Fuzzing Engine: $FUZZING_ENGINE
Max Length: $MAX_LEN bytes
RSS Limit: $RSS_LIMIT MB
Targets: ${SELECTED_TARGETS[*]}

EOF

    # Change to fuzz directory
    cd "$FUZZ_DIR"

    # Check if Cargo.toml exists
    if [[ ! -f "Cargo.toml" ]]; then
        log "ERROR" "Cargo.toml not found in $FUZZ_DIR"
        exit 1
    fi

    # Validate targets exist
    for target in "${SELECTED_TARGETS[@]}"; do
        if [[ ! -f "fuzz_targets/${target}.rs" ]]; then
            log "ERROR" "Fuzzing target $target not found"
            exit 1
        fi
    done

    log "SUCCESS" "Environment setup complete"
}

# Run fuzzing for a specific target
run_fuzzing_target() {
    local target="$1"
    local target_start_time=$(date +%s)

    log "INFO" "Starting fuzzing target: $target"

    # Create target-specific results directory
    local target_results_dir="$RESULTS_DIR/$target"
    mkdir -p "$target_results_dir"

    # Prepare fuzzing command based on engine
    local cmd_args=()
    local output_file="$target_results_dir/output.log"
    local stats_file="$target_results_dir/stats.txt"

    if [[ "$FUZZING_ENGINE" == "libfuzzer" ]]; then
        cmd_args=(
            "cargo" "fuzz" "run" "$target"
            "--"
            "-max_total_time=$DURATION"
            "-max_len=$MAX_LEN"
            "-rss_limit_mb=$RSS_LIMIT"
            "-print_final_stats=1"
            "-artifact_prefix=$target_results_dir/"
        )

        if [[ "${VERBOSE:-0}" == "1" ]]; then
            cmd_args+=("-verbosity=2")
        else
            cmd_args+=("-verbosity=0")
        fi

        if [[ "${JOBS:-}" != "" ]]; then
            cmd_args+=("-workers=$JOBS")
        fi

    elif [[ "$FUZZING_ENGINE" == "honggfuzz" ]]; then
        export HFUZZ_WORKSPACE="$target_results_dir"
        export HFUZZ_BUILD_ARGS="--features honggfuzz_fuzz"

        cmd_args=(
            "timeout" "${DURATION}s"
            "cargo" "hfuzz" "run" "$target"
            "--"
            "-t" "10"  # 10 second timeout per iteration
            "-x"       # Use Intel BTS/PT
        )

        if [[ "${JOBS:-}" != "" ]]; then
            cmd_args+=("-n" "$JOBS")
        fi

        if [[ "${VERBOSE:-0}" != "1" ]]; then
            cmd_args+=("-s")  # Silent mode
        fi
    fi

    # Create seed corpus if it doesn't exist
    local corpus_dir="corpus/$target"
    if [[ ! -d "$corpus_dir" ]]; then
        log "INFO" "Creating seed corpus for $target"
        mkdir -p "$corpus_dir"
        create_seed_corpus "$target" "$corpus_dir"
    fi

    # Run the fuzzing command
    log "DEBUG" "Running command: ${cmd_args[*]}"

    local exit_code=0
    if [[ "${QUIET:-0}" == "1" ]]; then
        "${cmd_args[@]}" > "$output_file" 2>&1 || exit_code=$?
    else
        "${cmd_args[@]}" 2>&1 | tee "$output_file" || exit_code=$?
    fi

    # Calculate execution time
    local target_end_time=$(date +%s)
    local target_duration=$((target_end_time - target_start_time))

    # Generate statistics
    generate_target_stats "$target" "$target_results_dir" "$target_duration" "$exit_code"

    if [[ $exit_code -eq 0 ]]; then
        log "SUCCESS" "Completed fuzzing target: $target (${target_duration}s)"
    else
        log "WARNING" "Fuzzing target $target completed with exit code: $exit_code"
    fi

    return $exit_code
}

# Create seed corpus for a target
create_seed_corpus() {
    local target="$1"
    local corpus_dir="$2"

    case "$target" in
        "fuzz_parser")
            cat > "$corpus_dir/basic.sol" << 'EOF'
pragma solidity ^0.8.0;
contract Test {
    function test() public pure returns (bool) {
        return true;
    }
}
EOF
            cat > "$corpus_dir/complex.sol" << 'EOF'
pragma solidity ^0.8.0;
contract Complex {
    mapping(address => uint256) balances;
    modifier onlyOwner() { _; }
    function transfer(address to, uint256 amount) public {
        balances[to] += amount;
    }
}
EOF
            ;;
        "fuzz_analyzer")
            echo '{"enabled_detectors":["reentrancy"],"severity_filter":"medium"}' > "$corpus_dir/config.json"
            ;;
        "fuzz_detectors")
            echo 'contract Test { function withdraw() public { msg.sender.call.value(1)(""); } }' > "$corpus_dir/reentrancy.sol"
            ;;
        "fuzz_solidity_generator")
            echo '{"complexity_level":"simple","include_events":true}' > "$corpus_dir/params.json"
            ;;
        "fuzz_sarif_output")
            cat > "$corpus_dir/basic.sarif" << 'EOF'
{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"test"}}}]}
EOF
            ;;
    esac
}

# Generate statistics for a target
generate_target_stats() {
    local target="$1"
    local results_dir="$2"
    local duration="$3"
    local exit_code="$4"

    local stats_file="$results_dir/stats.txt"
    local output_file="$results_dir/output.log"

    cat > "$stats_file" << EOF
Target: $target
Duration: ${duration}s
Exit Code: $exit_code
Engine: $FUZZING_ENGINE
Max Length: $MAX_LEN
RSS Limit: $RSS_LIMIT MB

EOF

    # Extract engine-specific statistics
    if [[ "$FUZZING_ENGINE" == "libfuzzer" && -f "$output_file" ]]; then
        echo "LibFuzzer Statistics:" >> "$stats_file"
        grep -E "(exec/s|cov:|ft:|corp:)" "$output_file" | tail -10 >> "$stats_file" || true

        # Check for crashes
        local crash_count=$(find "$results_dir" -name "crash-*" 2>/dev/null | wc -l)
        echo "Crashes Found: $crash_count" >> "$stats_file"

        # Check for timeouts
        local timeout_count=$(find "$results_dir" -name "timeout-*" 2>/dev/null | wc -l)
        echo "Timeouts Found: $timeout_count" >> "$stats_file"

    elif [[ "$FUZZING_ENGINE" == "honggfuzz" && -f "$output_file" ]]; then
        echo "Honggfuzz Statistics:" >> "$stats_file"
        grep -E "(Execs|Crashes|Timeouts)" "$output_file" | tail -5 >> "$stats_file" || true
    fi

    echo "" >> "$stats_file"
    echo "Generated at: $(date)" >> "$stats_file"
}

# Generate summary report
generate_summary_report() {
    local summary_file="$RESULTS_DIR/summary.txt"
    local run_end_time=$(date +%s)
    local total_duration=$((run_end_time - RUN_START_TIME))

    log "INFO" "Generating summary report..."

    cat > "$summary_file" << EOF
SolidityDefend Fuzzing Summary
==============================

Run Configuration:
- Start Time: $(date -d "@$RUN_START_TIME")
- End Time: $(date -d "@$run_end_time")
- Total Duration: ${total_duration}s
- Engine: $FUZZING_ENGINE
- Targets: ${SELECTED_TARGETS[*]}
- Duration per target: ${DURATION}s

Target Results:
EOF

    local total_crashes=0
    local total_timeouts=0
    local successful_targets=0

    for target in "${SELECTED_TARGETS[@]}"; do
        local target_results_dir="$RESULTS_DIR/$target"
        local stats_file="$target_results_dir/stats.txt"

        if [[ -f "$stats_file" ]]; then
            echo "" >> "$summary_file"
            echo "=== $target ===" >> "$summary_file"
            cat "$stats_file" >> "$summary_file"

            # Count crashes and timeouts
            local crashes=$(grep "Crashes Found:" "$stats_file" | awk '{print $3}' || echo "0")
            local timeouts=$(grep "Timeouts Found:" "$stats_file" | awk '{print $3}' || echo "0")

            total_crashes=$((total_crashes + crashes))
            total_timeouts=$((total_timeouts + timeouts))

            # Check if target completed successfully
            local exit_code=$(grep "Exit Code:" "$stats_file" | awk '{print $3}' || echo "1")
            if [[ "$exit_code" == "0" ]]; then
                successful_targets=$((successful_targets + 1))
            fi
        else
            echo "" >> "$summary_file"
            echo "=== $target ===" >> "$summary_file"
            echo "No statistics available (target may have failed to start)" >> "$summary_file"
        fi
    done

    cat >> "$summary_file" << EOF

Overall Summary:
- Successful Targets: $successful_targets/${#SELECTED_TARGETS[@]}
- Total Crashes Found: $total_crashes
- Total Timeouts Found: $total_timeouts
- Results Directory: $RESULTS_DIR

EOF

    # Log summary
    log "INFO" "Fuzzing run completed:"
    log "INFO" "  Successful targets: $successful_targets/${#SELECTED_TARGETS[@]}"
    log "INFO" "  Total crashes: $total_crashes"
    log "INFO" "  Total timeouts: $total_timeouts"
    log "INFO" "  Results saved to: $RESULTS_DIR"

    if [[ $total_crashes -gt 0 ]]; then
        log "WARNING" "Crashes were found! Review the results carefully."
    fi

    if [[ $successful_targets -eq ${#SELECTED_TARGETS[@]} ]]; then
        log "SUCCESS" "All fuzzing targets completed successfully"
    else
        log "WARNING" "Some fuzzing targets failed to complete"
    fi
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

    log "INFO" "Fuzzing run finished with exit code: $exit_code"
    exit $exit_code
}

# Main execution
main() {
    # Set default values
    local DURATION="$DEFAULT_DURATION"
    local FUZZING_ENGINE="libfuzzer"
    local MAX_LEN="$DEFAULT_MAX_LEN"
    local RSS_LIMIT="$DEFAULT_RSS_LIMIT"
    local JOBS=""
    local SELECTED_TARGETS=("${TARGETS[@]}")
    local CONTINUE="0"
    local VERBOSE="0"
    local QUIET="0"

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--duration)
                DURATION="$2"
                shift 2
                ;;
            -t|--targets)
                IFS=',' read -ra SELECTED_TARGETS <<< "$2"
                shift 2
                ;;
            -e|--engine)
                FUZZING_ENGINE="$2"
                if [[ "$FUZZING_ENGINE" != "libfuzzer" && "$FUZZING_ENGINE" != "honggfuzz" ]]; then
                    log "ERROR" "Invalid engine: $FUZZING_ENGINE"
                    exit 1
                fi
                shift 2
                ;;
            -j|--jobs)
                JOBS="$2"
                shift 2
                ;;
            -m|--max-len)
                MAX_LEN="$2"
                shift 2
                ;;
            -r|--rss-limit)
                RSS_LIMIT="$2"
                shift 2
                ;;
            -c|--continue)
                CONTINUE="1"
                shift
                ;;
            -v|--verbose)
                VERBOSE="1"
                shift
                ;;
            -q|--quiet)
                QUIET="1"
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Validate numeric arguments
    if ! [[ "$DURATION" =~ ^[0-9]+$ ]]; then
        log "ERROR" "Duration must be a positive integer"
        exit 1
    fi

    if ! [[ "$MAX_LEN" =~ ^[0-9]+$ ]]; then
        log "ERROR" "Max length must be a positive integer"
        exit 1
    fi

    if ! [[ "$RSS_LIMIT" =~ ^[0-9]+$ ]]; then
        log "ERROR" "RSS limit must be a positive integer"
        exit 1
    fi

    if [[ "$JOBS" != "" ]] && ! [[ "$JOBS" =~ ^[0-9]+$ ]]; then
        log "ERROR" "Jobs must be a positive integer"
        exit 1
    fi

    # Auto-detect jobs if not specified
    if [[ "$JOBS" == "" ]]; then
        JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "1")
        # Use half the available cores for fuzzing
        JOBS=$((JOBS / 2))
        if [[ $JOBS -lt 1 ]]; then
            JOBS=1
        fi
    fi

    # Setup signal handlers
    local CLEANUP_PIDS=()
    trap cleanup EXIT INT TERM

    # Record start time
    local RUN_START_TIME=$(date +%s)

    # Check dependencies and setup environment
    check_dependencies
    setup_environment

    log "INFO" "Starting fuzzing run with $FUZZING_ENGINE"
    log "INFO" "Selected targets: ${SELECTED_TARGETS[*]}"
    log "INFO" "Duration per target: ${DURATION}s"
    log "INFO" "Using $JOBS parallel jobs"

    # Run fuzzing for each target
    local failed_targets=()
    for target in "${SELECTED_TARGETS[@]}"; do
        if ! run_fuzzing_target "$target"; then
            failed_targets+=("$target")
        fi
    done

    # Generate summary report
    generate_summary_report

    # Exit with error if any targets failed
    if [[ ${#failed_targets[@]} -gt 0 ]]; then
        log "ERROR" "Failed targets: ${failed_targets[*]}"
        exit 1
    fi

    log "SUCCESS" "All fuzzing targets completed successfully"
}

# Run main function with all arguments
main "$@"