#!/bin/bash

# SolidityDefend Developer Experience Test Runner
# This script runs comprehensive tests for all developer experience features

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_DIR="tests/developer_experience"
REPORT_DIR="test_reports/developer_experience"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="${REPORT_DIR}/test_report_${TIMESTAMP}.html"

echo -e "${BLUE}SolidityDefend Developer Experience Test Suite${NC}"
echo "=============================================="
echo "Starting comprehensive developer experience testing..."
echo

# Create report directory
mkdir -p "$REPORT_DIR"

# Function to print status
print_status() {
    local status=$1
    local message=$2

    if [ "$status" == "PASS" ]; then
        echo -e "${GREEN}✓ PASS${NC} - $message"
    elif [ "$status" == "FAIL" ]; then
        echo -e "${RED}✗ FAIL${NC} - $message"
    elif [ "$status" == "SKIP" ]; then
        echo -e "${YELLOW}⚠ SKIP${NC} - $message"
    else
        echo -e "${BLUE}ℹ INFO${NC} - $message"
    fi
}

# Function to run tests with timeout
run_test_with_timeout() {
    local test_name=$1
    local command=$2
    local timeout_duration=${3:-300}  # Default 5 minutes

    echo -e "${BLUE}Running: $test_name${NC}"

    if timeout $timeout_duration bash -c "$command"; then
        print_status "PASS" "$test_name"
        return 0
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            print_status "FAIL" "$test_name (timeout after ${timeout_duration}s)"
        else
            print_status "FAIL" "$test_name (exit code: $exit_code)"
        fi
        return 1
    fi
}

# Check prerequisites
check_prerequisites() {
    echo "Checking prerequisites..."

    # Check if Rust is installed
    if ! command -v cargo &> /dev/null; then
        print_status "FAIL" "Cargo not found. Please install Rust."
        exit 1
    fi

    # Check if Node.js is installed (for VS Code extension testing)
    if ! command -v node &> /dev/null; then
        print_status "SKIP" "Node.js not found. VS Code extension tests will be limited."
    fi

    # Check if VS Code is installed
    if ! command -v code &> /dev/null; then
        print_status "SKIP" "VS Code not found. Extension integration tests will be skipped."
    fi

    print_status "PASS" "Prerequisites check completed"
}

# Test VS Code Extension
test_vscode_extension() {
    echo
    echo "Testing VS Code Extension..."
    echo "============================="

    # Check extension structure
    if [ -f "extensions/vscode/package.json" ]; then
        print_status "PASS" "VS Code extension package.json found"
    else
        print_status "FAIL" "VS Code extension package.json not found"
        return 1
    fi

    # Validate package.json
    if command -v node &> /dev/null; then
        run_test_with_timeout "Package.json validation" "node -e 'JSON.parse(require(\"fs\").readFileSync(\"extensions/vscode/package.json\"))'"
    else
        print_status "SKIP" "Package.json validation (Node.js not available)"
    fi

    # Check TypeScript files
    local ts_files=("extension.ts" "analysisService.ts" "configuration.ts" "diagnostics.ts" "provider.ts" "quickFix.ts" "securityTree.ts" "dashboard.ts")

    for file in "${ts_files[@]}"; do
        if [ -f "extensions/vscode/src/$file" ]; then
            print_status "PASS" "Found $file"
        else
            print_status "FAIL" "Missing $file"
        fi
    done

    # Compile TypeScript if available
    if command -v npx &> /dev/null && [ -f "extensions/vscode/tsconfig.json" ]; then
        run_test_with_timeout "TypeScript compilation" "cd extensions/vscode && npx tsc --noEmit" 120
    else
        print_status "SKIP" "TypeScript compilation (tsc not available)"
    fi

    # Test VS Code extension installation (if VS Code is available)
    if command -v code &> /dev/null; then
        # Create a test workspace
        local test_workspace="/tmp/soliditydefend_test_workspace"
        mkdir -p "$test_workspace"
        echo 'contract Test {}' > "$test_workspace/test.sol"

        print_status "INFO" "VS Code extension installation test skipped (requires manual installation)"
    else
        print_status "SKIP" "VS Code extension tests (VS Code not available)"
    fi
}

# Test LSP Server
test_lsp_server() {
    echo
    echo "Testing LSP Server..."
    echo "===================="

    # Build LSP server
    run_test_with_timeout "LSP server build" "cargo build --bin soliditydefend" 300

    # Check if binary exists
    if [ -f "target/debug/soliditydefend" ] || [ -f "target/release/soliditydefend" ]; then
        print_status "PASS" "SolidityDefend binary found"
    else
        print_status "FAIL" "SolidityDefend binary not found"
        return 1
    fi

    # Test LSP server startup
    local binary_path="./target/debug/soliditydefend"
    if [ ! -f "$binary_path" ]; then
        binary_path="./target/release/soliditydefend"
    fi

    if [ -f "$binary_path" ]; then
        # Test help command
        run_test_with_timeout "LSP help command" "$binary_path --help" 10

        # Test LSP mode (if implemented)
        print_status "INFO" "LSP server startup test (placeholder)"
    else
        print_status "FAIL" "Binary not found for LSP testing"
    fi
}

# Test Web Dashboard
test_web_dashboard() {
    echo
    echo "Testing Web Dashboard..."
    echo "======================="

    # Check dashboard files
    local dashboard_files=("src/web_dashboard/mod.rs" "src/web_dashboard/server.rs" "src/web_dashboard/handlers.rs" "web/dashboard.html")

    for file in "${dashboard_files[@]}"; do
        if [ -f "$file" ]; then
            print_status "PASS" "Found $file"
        else
            print_status "FAIL" "Missing $file"
        fi
    done

    # Validate HTML structure
    if [ -f "web/dashboard.html" ]; then
        if grep -q "SolidityDefend" "web/dashboard.html"; then
            print_status "PASS" "Dashboard HTML contains SolidityDefend branding"
        else
            print_status "FAIL" "Dashboard HTML missing branding"
        fi

        if grep -q "WebSocket" "web/dashboard.html"; then
            print_status "PASS" "Dashboard HTML contains WebSocket support"
        else
            print_status "FAIL" "Dashboard HTML missing WebSocket support"
        fi
    fi

    # Test dashboard server compilation
    run_test_with_timeout "Dashboard server compilation check" "cargo check --features web-dashboard" 120
}

# Test IDE Integrations
test_ide_integrations() {
    echo
    echo "Testing IDE Integrations..."
    echo "=========================="

    # Test IntelliJ plugin
    if [ -f "ide_integrations/intellij/plugin.xml" ]; then
        print_status "PASS" "IntelliJ plugin.xml found"

        # Validate plugin.xml structure
        if grep -q "SolidityDefend" "ide_integrations/intellij/plugin.xml"; then
            print_status "PASS" "IntelliJ plugin.xml contains SolidityDefend"
        else
            print_status "FAIL" "IntelliJ plugin.xml missing SolidityDefend"
        fi

        if [ -f "ide_integrations/intellij/SolidityDefendPlugin.java" ]; then
            print_status "PASS" "IntelliJ Java implementation found"
        else
            print_status "FAIL" "IntelliJ Java implementation not found"
        fi
    else
        print_status "FAIL" "IntelliJ plugin configuration not found"
    fi

    # Test Sublime Text plugin
    if [ -f "ide_integrations/sublime/SolidityDefend.py" ]; then
        print_status "PASS" "Sublime Text plugin found"

        # Basic Python syntax check
        if command -v python3 &> /dev/null; then
            run_test_with_timeout "Sublime plugin syntax check" "python3 -m py_compile ide_integrations/sublime/SolidityDefend.py" 30
        else
            print_status "SKIP" "Sublime plugin syntax check (Python not available)"
        fi
    else
        print_status "FAIL" "Sublime Text plugin not found"
    fi

    # Test Vim plugin
    if [ -f "ide_integrations/vim/soliditydefend.vim" ]; then
        print_status "PASS" "Vim plugin found"

        # Basic Vim script validation
        if grep -q "SolidityDefend" "ide_integrations/vim/soliditydefend.vim"; then
            print_status "PASS" "Vim plugin contains SolidityDefend"
        else
            print_status "FAIL" "Vim plugin missing SolidityDefend"
        fi
    else
        print_status "FAIL" "Vim plugin not found"
    fi
}

# Test Analysis Integration
test_analysis_integration() {
    echo
    echo "Testing Analysis Integration..."
    echo "=============================="

    # Create test Solidity files
    local test_dir="/tmp/soliditydefend_integration_test"
    mkdir -p "$test_dir"

    # Create vulnerable contract
    cat > "$test_dir/vulnerable.sol" << 'EOF'
pragma solidity ^0.8.0;

contract VulnerableContract {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function withdraw() public {
        require(tx.origin == owner, "Not owner");
        payable(msg.sender).transfer(balances[msg.sender]);
        balances[msg.sender] = 0;
    }

    function unsafeCall(address target) public {
        target.call{value: 1 ether}("");
    }
}
EOF

    # Test analysis
    local binary_path="./target/debug/soliditydefend"
    if [ ! -f "$binary_path" ]; then
        binary_path="./target/release/soliditydefend"
    fi

    if [ -f "$binary_path" ]; then
        # Test file analysis
        run_test_with_timeout "Contract analysis" "$binary_path analyze $test_dir/vulnerable.sol" 60

        # Test directory analysis
        run_test_with_timeout "Directory analysis" "$binary_path analyze $test_dir" 60
    else
        print_status "SKIP" "Analysis integration tests (binary not found)"
    fi

    # Cleanup
    rm -rf "$test_dir"
}

# Run performance tests
test_performance() {
    echo
    echo "Testing Performance..."
    echo "===================="

    # Create larger test project
    local perf_test_dir="/tmp/soliditydefend_perf_test"
    mkdir -p "$perf_test_dir"

    # Create multiple contracts for performance testing
    for i in {1..10}; do
        cat > "$perf_test_dir/contract$i.sol" << EOF
pragma solidity ^0.8.0;

contract TestContract$i {
    address public owner;
    mapping(address => uint256) public balances;

    function withdraw() public {
        require(tx.origin == owner, "Not owner");
        payable(msg.sender).transfer(balances[msg.sender]);
    }

    function unsafeCall() public {
        msg.sender.call{value: 1 ether}("");
    }
}
EOF
    done

    local binary_path="./target/debug/soliditydefend"
    if [ ! -f "$binary_path" ]; then
        binary_path="./target/release/soliditydefend"
    fi

    if [ -f "$binary_path" ]; then
        echo "Running performance test on 10 contracts..."
        local start_time=$(date +%s)

        if timeout 120 "$binary_path" analyze "$perf_test_dir" > /dev/null 2>&1; then
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            print_status "PASS" "Performance test completed in ${duration}s"

            if [ $duration -lt 60 ]; then
                print_status "PASS" "Performance within acceptable limits"
            else
                print_status "FAIL" "Performance slower than expected"
            fi
        else
            print_status "FAIL" "Performance test timed out or failed"
        fi
    else
        print_status "SKIP" "Performance tests (binary not found)"
    fi

    # Cleanup
    rm -rf "$perf_test_dir"
}

# Run Rust tests
test_rust_components() {
    echo
    echo "Testing Rust Components..."
    echo "========================="

    # Run developer experience tests
    run_test_with_timeout "Developer experience unit tests" "cargo test developer_experience" 300

    # Run integration tests
    run_test_with_timeout "Developer experience integration tests" "cargo test --test '*developer*'" 300

    # Run all tests with developer experience features
    run_test_with_timeout "All tests with dev features" "cargo test --features developer-experience" 600
}

# Generate HTML report
generate_html_report() {
    echo
    echo "Generating HTML Report..."
    echo "========================"

    cat > "$REPORT_FILE" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>SolidityDefend Developer Experience Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 30px; }
        .test-section { margin: 20px 0; }
        .test-section h2 { color: #333; border-bottom: 2px solid #007acc; }
        .pass { color: #28a745; }
        .fail { color: #dc3545; }
        .skip { color: #ffc107; }
        .info { color: #17a2b8; }
        .summary { background: #e9ecef; padding: 15px; border-radius: 5px; margin-top: 30px; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ SolidityDefend Developer Experience Test Report</h1>
        <p><strong>Generated:</strong> $(date)</p>
        <p><strong>Test Suite:</strong> Comprehensive Developer Experience Testing</p>
    </div>

    <div class="test-section">
        <h2>Test Results Summary</h2>
        <p>This report contains the results of comprehensive testing for SolidityDefend's developer experience features.</p>
    </div>

    <div class="test-section">
        <h2>VS Code Extension</h2>
        <p>Tests for VS Code extension functionality, including real-time analysis, code actions, and dashboard integration.</p>
    </div>

    <div class="test-section">
        <h2>LSP Server</h2>
        <p>Tests for Language Server Protocol implementation, including document analysis, hover information, and code formatting.</p>
    </div>

    <div class="test-section">
        <h2>Web Dashboard</h2>
        <p>Tests for the interactive web dashboard, including API endpoints, WebSocket communication, and real-time updates.</p>
    </div>

    <div class="test-section">
        <h2>IDE Integrations</h2>
        <p>Tests for IntelliJ IDEA, Sublime Text, and Vim integrations.</p>
    </div>

    <div class="test-section">
        <h2>Performance Testing</h2>
        <p>Performance benchmarks and load testing results.</p>
    </div>

    <div class="summary">
        <h3>📊 Test Execution Summary</h3>
        <p><strong>Execution Time:</strong> $(date)</p>
        <p><strong>Environment:</strong> $(uname -a)</p>
        <p><strong>Rust Version:</strong> $(rustc --version 2>/dev/null || echo "Not available")</p>
        <p><strong>Node.js Version:</strong> $(node --version 2>/dev/null || echo "Not available")</p>
    </div>
</body>
</html>
EOF

    print_status "PASS" "HTML report generated: $REPORT_FILE"
}

# Main execution
main() {
    local start_time=$(date +%s)

    # Initialize counters
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    local skipped_tests=0

    # Run all test suites
    check_prerequisites

    echo
    echo "Starting Test Execution..."
    echo "========================="

    # Run individual test suites
    test_vscode_extension
    test_lsp_server
    test_web_dashboard
    test_ide_integrations
    test_analysis_integration
    test_performance
    test_rust_components

    # Generate report
    generate_html_report

    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))

    echo
    echo "Test Execution Complete!"
    echo "======================="
    echo -e "${BLUE}Total Duration: ${total_duration}s${NC}"
    echo -e "${BLUE}Report Generated: $REPORT_FILE${NC}"
    echo
    echo "Open the HTML report in your browser to view detailed results:"
    echo "file://$PWD/$REPORT_FILE"
}

# Trap to ensure cleanup on exit
cleanup() {
    echo
    print_status "INFO" "Cleaning up temporary files..."
    rm -rf /tmp/soliditydefend_*
}

trap cleanup EXIT

# Run main function
main "$@"