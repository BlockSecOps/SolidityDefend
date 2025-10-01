#!/bin/bash
set -euo pipefail

# Flamegraph profiling script for SolidityDefend
# Generates CPU and memory flamegraphs for performance analysis

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Color output functions
red() { echo -e "\033[31m$*\033[0m"; }
green() { echo -e "\033[32m$*\033[0m"; }
yellow() { echo -e "\033[33m$*\033[0m"; }
blue() { echo -e "\033[34m$*\033[0m"; }

# Default values
PROFILE_TYPE="cpu"
OUTPUT_DIR="target/profiling"
DURATION="30"
FREQUENCY="99"
TARGET_BINARY=""
ARGS=""
FLAME_GRAPH_DIR=""
SUDO_REQUIRED=false

usage() {
    cat << EOF
Usage: $0 [OPTIONS] [-- BINARY_ARGS]

Generate flamegraphs for SolidityDefend performance profiling

OPTIONS:
    -t, --type TYPE         Profile type: cpu, memory, io (default: cpu)
    -o, --output DIR        Output directory (default: target/profiling)
    -d, --duration SECS     Profiling duration in seconds (default: 30)
    -f, --frequency HZ      Sampling frequency (default: 99)
    -b, --binary PATH       Target binary path
    --flame-graph-dir DIR   Path to FlameGraph tools
    --sudo                  Use sudo for system profiling
    -h, --help              Show this help

EXAMPLES:
    $0                                          # Profile default binary for 30s
    $0 -t memory -d 60                         # Memory profile for 60s
    $0 -b ./target/release/soliditydefend      # Profile specific binary
    $0 -- contracts/test.sol                   # Profile with arguments

DEPENDENCIES:
    - perf (Linux) or dtrace (macOS)
    - FlameGraph tools (https://github.com/brendangregg/FlameGraph)
    - cargo-flamegraph (for Rust integration)

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type)
            PROFILE_TYPE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -f|--frequency)
            FREQUENCY="$2"
            shift 2
            ;;
        -b|--binary)
            TARGET_BINARY="$2"
            shift 2
            ;;
        --flame-graph-dir)
            FLAME_GRAPH_DIR="$2"
            shift 2
            ;;
        --sudo)
            SUDO_REQUIRED=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            ARGS="$*"
            break
            ;;
        *)
            red "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Detect OS and set appropriate tools
OS="$(uname -s)"
case "$OS" in
    Linux*)
        PROFILER="perf"
        ;;
    Darwin*)
        PROFILER="dtrace"
        yellow "Note: macOS profiling requires SIP to be disabled for some features"
        ;;
    *)
        red "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Check for required tools
check_dependencies() {
    blue "Checking dependencies..."

    # Check profiler
    if ! command -v "$PROFILER" &> /dev/null; then
        red "Error: $PROFILER is not installed"
        case "$OS" in
            Linux*)
                echo "Install with: sudo apt-get install linux-tools-common linux-tools-generic"
                ;;
            Darwin*)
                echo "Dtrace should be available on macOS by default"
                ;;
        esac
        exit 1
    fi
    green "✓ $PROFILER is available"

    # Check FlameGraph tools
    if [[ -z "$FLAME_GRAPH_DIR" ]]; then
        # Try to find FlameGraph tools
        for dir in "/opt/FlameGraph" "$HOME/FlameGraph" "$(pwd)/FlameGraph"; do
            if [[ -f "$dir/flamegraph.pl" ]]; then
                FLAME_GRAPH_DIR="$dir"
                break
            fi
        done
    fi

    if [[ -z "$FLAME_GRAPH_DIR" ]] || [[ ! -f "$FLAME_GRAPH_DIR/flamegraph.pl" ]]; then
        yellow "Warning: FlameGraph tools not found"
        echo "Install with:"
        echo "  git clone https://github.com/brendangregg/FlameGraph.git"
        echo "  export PATH=\$PATH:\$(pwd)/FlameGraph"
        echo "Or specify path with --flame-graph-dir"

        # Try cargo-flamegraph as alternative
        if command -v cargo-flamegraph &> /dev/null; then
            blue "Using cargo-flamegraph as alternative"
            FLAME_GRAPH_DIR="cargo-flamegraph"
        else
            red "Error: No flamegraph tools available"
            echo "Install cargo-flamegraph with: cargo install flamegraph"
            exit 1
        fi
    else
        green "✓ FlameGraph tools found at $FLAME_GRAPH_DIR"
    fi

    # Check Rust toolchain
    if ! command -v cargo &> /dev/null; then
        red "Error: Cargo is not installed"
        exit 1
    fi
    green "✓ Cargo is available"
}

# Build target binary if not specified
prepare_binary() {
    if [[ -z "$TARGET_BINARY" ]]; then
        blue "Building SolidityDefend binary..."
        cargo build --release --bin soliditydefend
        TARGET_BINARY="./target/release/soliditydefend"
    fi

    if [[ ! -f "$TARGET_BINARY" ]]; then
        red "Error: Binary not found at $TARGET_BINARY"
        exit 1
    fi

    green "✓ Target binary: $TARGET_BINARY"
}

# Create output directory
prepare_output() {
    mkdir -p "$OUTPUT_DIR"
    blue "Output directory: $OUTPUT_DIR"
}

# Generate CPU flamegraph
profile_cpu() {
    blue "Generating CPU flamegraph..."

    local output_file="$OUTPUT_DIR/cpu-$(date +%Y%m%d-%H%M%S).svg"
    local perf_data="$OUTPUT_DIR/perf.data"

    case "$OS" in
        Linux*)
            if [[ "$SUDO_REQUIRED" == "true" ]]; then
                SUDO_CMD="sudo"
            else
                SUDO_CMD=""
            fi

            blue "Recording perf data for ${DURATION}s..."
            $SUDO_CMD perf record -F "$FREQUENCY" -g --call-graph=dwarf \
                -o "$perf_data" -- "$TARGET_BINARY" $ARGS &

            local perf_pid=$!
            sleep "$DURATION"

            # Stop perf recording gracefully
            kill -TERM $perf_pid 2>/dev/null || true
            wait $perf_pid 2>/dev/null || true

            blue "Generating flamegraph..."
            if [[ "$FLAME_GRAPH_DIR" == "cargo-flamegraph" ]]; then
                # Use cargo-flamegraph
                CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph \
                    --output "$output_file" \
                    --bin soliditydefend -- $ARGS
            else
                # Use FlameGraph tools
                perf script -i "$perf_data" | \
                    "$FLAME_GRAPH_DIR/stackcollapse-perf.pl" | \
                    "$FLAME_GRAPH_DIR/flamegraph.pl" > "$output_file"
            fi
            ;;

        Darwin*)
            blue "Recording dtrace data for ${DURATION}s..."
            if [[ "$FLAME_GRAPH_DIR" == "cargo-flamegraph" ]]; then
                CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph \
                    --output "$output_file" \
                    --bin soliditydefend -- $ARGS
            else
                # Use dtrace directly
                sudo dtrace -x stackframes=100 -n "profile-$FREQUENCY /pid == \$target/ { @[stack()] = count(); }" \
                    -c "$TARGET_BINARY $ARGS" -o "$OUTPUT_DIR/dtrace.out"

                "$FLAME_GRAPH_DIR/stackcollapse-dtrace.pl" "$OUTPUT_DIR/dtrace.out" | \
                    "$FLAME_GRAPH_DIR/flamegraph.pl" > "$output_file"
            fi
            ;;
    esac

    green "✓ CPU flamegraph generated: $output_file"
}

# Generate memory flamegraph
profile_memory() {
    blue "Generating memory flamegraph..."

    local output_file="$OUTPUT_DIR/memory-$(date +%Y%m%d-%H%M%S).svg"

    case "$OS" in
        Linux*)
            if ! command -v valgrind &> /dev/null; then
                yellow "Warning: valgrind not found, using perf for memory profiling"
                profile_memory_perf "$output_file"
                return
            fi

            blue "Recording memory allocations with valgrind..."
            valgrind --tool=massif --massif-out-file="$OUTPUT_DIR/massif.out" \
                "$TARGET_BINARY" $ARGS

            # Convert massif output to flamegraph format
            if [[ -f "$FLAME_GRAPH_DIR/massif-flamegraph.pl" ]]; then
                "$FLAME_GRAPH_DIR/massif-flamegraph.pl" "$OUTPUT_DIR/massif.out" > "$output_file"
            else
                yellow "massif-flamegraph.pl not found, generating basic memory report"
                ms_print "$OUTPUT_DIR/massif.out" > "$OUTPUT_DIR/memory-report.txt"
                echo "Memory report saved to $OUTPUT_DIR/memory-report.txt"
            fi
            ;;

        Darwin*)
            blue "Recording memory allocations with Instruments..."
            # Use Xcode Instruments for memory profiling on macOS
            xcrun xctrace record --template 'Allocations' \
                --launch "$TARGET_BINARY" --args $ARGS \
                --output "$OUTPUT_DIR/allocations.trace"

            # Convert to flamegraph (requires custom processing)
            yellow "Manual conversion required for macOS Instruments data"
            echo "Trace file saved to $OUTPUT_DIR/allocations.trace"
            echo "Open with Instruments for analysis"
            ;;
    esac

    green "✓ Memory profiling completed"
}

# Memory profiling with perf (Linux fallback)
profile_memory_perf() {
    local output_file="$1"

    blue "Using perf for memory profiling..."

    # Record memory-related events
    sudo perf record -e cache-misses,cache-references,page-faults \
        -g --call-graph=dwarf -o "$OUTPUT_DIR/perf-memory.data" \
        -- "$TARGET_BINARY" $ARGS

    # Generate flamegraph
    perf script -i "$OUTPUT_DIR/perf-memory.data" | \
        "$FLAME_GRAPH_DIR/stackcollapse-perf.pl" | \
        "$FLAME_GRAPH_DIR/flamegraph.pl" --title="Memory Events" > "$output_file"

    green "✓ Memory flamegraph generated: $output_file"
}

# Generate I/O flamegraph
profile_io() {
    blue "Generating I/O flamegraph..."

    local output_file="$OUTPUT_DIR/io-$(date +%Y%m%d-%H%M%S).svg"

    case "$OS" in
        Linux*)
            blue "Recording I/O events with perf..."
            sudo perf record -e syscalls:sys_enter_read,syscalls:sys_enter_write,syscalls:sys_enter_open \
                -g --call-graph=dwarf -o "$OUTPUT_DIR/perf-io.data" \
                -- "$TARGET_BINARY" $ARGS

            perf script -i "$OUTPUT_DIR/perf-io.data" | \
                "$FLAME_GRAPH_DIR/stackcollapse-perf.pl" | \
                "$FLAME_GRAPH_DIR/flamegraph.pl" --title="I/O Operations" > "$output_file"
            ;;

        Darwin*)
            blue "Recording I/O events with dtrace..."
            sudo dtrace -n "syscall::read:entry,syscall::write:entry /pid == \$target/ { @[stack()] = count(); }" \
                -c "$TARGET_BINARY $ARGS" -o "$OUTPUT_DIR/dtrace-io.out"

            "$FLAME_GRAPH_DIR/stackcollapse-dtrace.pl" "$OUTPUT_DIR/dtrace-io.out" | \
                "$FLAME_GRAPH_DIR/flamegraph.pl" --title="I/O Operations" > "$output_file"
            ;;
    esac

    green "✓ I/O flamegraph generated: $output_file"
}

# Generate comprehensive performance report
generate_report() {
    local report_file="$OUTPUT_DIR/performance-report-$(date +%Y%m%d-%H%M%S).md"

    blue "Generating performance report..."

    cat > "$report_file" << EOF
# SolidityDefend Performance Report

Generated on: $(date)
Binary: $TARGET_BINARY
Profile Type: $PROFILE_TYPE
Duration: ${DURATION}s
Arguments: $ARGS

## System Information

- OS: $OS
- Profiler: $PROFILER
- CPU Cores: $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "unknown")
- Memory: $(free -h 2>/dev/null | grep Mem | awk '{print $2}' || echo "unknown")

## Files Generated

EOF

    # List generated files
    find "$OUTPUT_DIR" -name "*.svg" -o -name "*.txt" -o -name "*.data" -o -name "*.out" | \
        sort | while read -r file; do
        echo "- $(basename "$file")" >> "$report_file"
    done

    cat >> "$report_file" << EOF

## Usage Instructions

### Viewing Flamegraphs
1. Open .svg files in a web browser
2. Click on stack frames to zoom in
3. Use browser search to find specific functions

### Analyzing Results
- Wider flames = more CPU time or memory usage
- Look for unexpected wide frames (performance bottlenecks)
- Compare before/after optimization runs

### Next Steps
1. Identify hot paths in the flamegraph
2. Profile specific functions with more detail
3. Implement optimizations
4. Re-run profiling to measure improvements

EOF

    green "✓ Performance report generated: $report_file"
}

# Cleanup function
cleanup() {
    blue "Cleaning up temporary files..."
    rm -f "$OUTPUT_DIR"/*.data "$OUTPUT_DIR"/*.out 2>/dev/null || true
}

# Main execution
main() {
    blue "Starting SolidityDefend performance profiling..."

    check_dependencies
    prepare_binary
    prepare_output

    case "$PROFILE_TYPE" in
        cpu)
            profile_cpu
            ;;
        memory)
            profile_memory
            ;;
        io)
            profile_io
            ;;
        all)
            profile_cpu
            profile_memory
            profile_io
            ;;
        *)
            red "Error: Unknown profile type: $PROFILE_TYPE"
            echo "Supported types: cpu, memory, io, all"
            exit 1
            ;;
    esac

    generate_report
    cleanup

    green "🎉 Performance profiling completed!"
    echo
    blue "Results saved in: $OUTPUT_DIR"
    echo "Open .svg files in a web browser to view flamegraphs"
}

# Handle script interruption
trap cleanup EXIT INT TERM

# Run main function
main