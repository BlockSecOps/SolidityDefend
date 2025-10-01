#!/bin/bash
set -euo pipefail

# CI Build Script for SolidityDefend
# Optimized for CI/CD environments

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# CI environment detection
CI_PLATFORM="unknown"
if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    CI_PLATFORM="github"
elif [[ "${GITLAB_CI:-}" == "true" ]]; then
    CI_PLATFORM="gitlab"
elif [[ "${JENKINS_URL:-}" != "" ]]; then
    CI_PLATFORM="jenkins"
elif [[ "${CI:-}" == "true" ]]; then
    CI_PLATFORM="generic"
fi

# Default values
BUILD_TYPE="release"
RUN_TESTS="true"
RUN_LINTS="true"
GENERATE_DOCS="false"
TARGET=""
FEATURES=""
OUTPUT_DIR="target"

# Color output (disabled in CI by default)
if [[ "${NO_COLOR:-}" == "1" ]] || [[ "${CI:-}" == "true" ]]; then
    red() { echo "$*"; }
    green() { echo "$*"; }
    yellow() { echo "$*"; }
    blue() { echo "$*"; }
else
    red() { echo -e "\033[31m$*\033[0m"; }
    green() { echo -e "\033[32m$*\033[0m"; }
    yellow() { echo -e "\033[33m$*\033[0m"; }
    blue() { echo -e "\033[34m$*\033[0m"; }
fi

log_section() {
    echo
    blue "==== $1 ===="
}

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

CI build script for SolidityDefend

OPTIONS:
    --build-type TYPE      Build type: debug, release (default: release)
    --target TARGET        Cargo target triple
    --features FEATURES    Cargo features to enable
    --no-tests             Skip running tests
    --no-lints             Skip linting
    --docs                 Generate documentation
    --output-dir DIR       Output directory (default: target)
    -h, --help             Show this help

ENVIRONMENT VARIABLES:
    CI_CACHE_KEY          Cache key for dependency caching
    CI_ARTIFACT_NAME      Name for build artifacts
    RUST_LOG              Rust logging level (default: info)

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --build-type)
            BUILD_TYPE="$2"
            shift 2
            ;;
        --target)
            TARGET="$2"
            shift 2
            ;;
        --features)
            FEATURES="$2"
            shift 2
            ;;
        --no-tests)
            RUN_TESTS="false"
            shift
            ;;
        --no-lints)
            RUN_LINTS="false"
            shift
            ;;
        --docs)
            GENERATE_DOCS="true"
            shift
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            red "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# CI platform specific setup
log_section "CI Environment Setup"
echo "CI Platform: $CI_PLATFORM"
echo "Build Type: $BUILD_TYPE"
echo "Rust Version: $(rustc --version)"
echo "Cargo Version: $(cargo --version)"

case "$CI_PLATFORM" in
    github)
        echo "GitHub Actions detected"
        # GitHub Actions specific optimizations
        export CARGO_INCREMENTAL=0
        export RUSTFLAGS="-D warnings"
        ;;
    gitlab)
        echo "GitLab CI detected"
        # GitLab CI specific optimizations
        export CARGO_HOME="${CI_PROJECT_DIR}/.cargo"
        ;;
    jenkins)
        echo "Jenkins detected"
        ;;
    *)
        echo "Generic CI or local environment"
        ;;
esac

# Set Rust environment
export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE=1

# Prepare cargo arguments
CARGO_ARGS=()
if [[ "$BUILD_TYPE" == "release" ]]; then
    CARGO_ARGS+=("--release")
fi

if [[ -n "$TARGET" ]]; then
    CARGO_ARGS+=("--target" "$TARGET")
fi

if [[ -n "$FEATURES" ]]; then
    CARGO_ARGS+=("--features" "$FEATURES")
fi

# Check for required tools
log_section "Tool Verification"
for tool in cargo rustc; do
    if ! command -v "$tool" &> /dev/null; then
        red "Error: $tool is not installed"
        exit 1
    fi
    green "✓ $tool is available"
done

# Update dependencies
log_section "Dependency Update"
cargo fetch
green "✓ Dependencies fetched"

# Run linting
if [[ "$RUN_LINTS" == "true" ]]; then
    log_section "Code Linting"

    # Check formatting
    if cargo fmt --version &> /dev/null; then
        blue "Checking code formatting..."
        cargo fmt --all -- --check
        green "✓ Code formatting OK"
    else
        yellow "⚠ rustfmt not available, skipping format check"
    fi

    # Run clippy
    if cargo clippy --version &> /dev/null; then
        blue "Running clippy..."
        cargo clippy "${CARGO_ARGS[@]}" --all-targets --all-features -- -D warnings
        green "✓ Clippy checks passed"
    else
        yellow "⚠ clippy not available, skipping lint check"
    fi
fi

# Run tests
if [[ "$RUN_TESTS" == "true" ]]; then
    log_section "Running Tests"

    # Unit tests
    blue "Running unit tests..."
    cargo test "${CARGO_ARGS[@]}" --lib
    green "✓ Unit tests passed"

    # Integration tests
    blue "Running integration tests..."
    cargo test "${CARGO_ARGS[@]}" --test '*'
    green "✓ Integration tests passed"

    # Doc tests
    blue "Running doc tests..."
    cargo test "${CARGO_ARGS[@]}" --doc
    green "✓ Doc tests passed"
fi

# Build the project
log_section "Building Project"
blue "Building SolidityDefend..."
cargo build "${CARGO_ARGS[@]}"
green "✓ Build completed successfully"

# Generate documentation if requested
if [[ "$GENERATE_DOCS" == "true" ]]; then
    log_section "Generating Documentation"
    cargo doc "${CARGO_ARGS[@]}" --no-deps --document-private-items
    green "✓ Documentation generated"
fi

# Prepare artifacts
log_section "Preparing Artifacts"
ARTIFACT_DIR="$OUTPUT_DIR/ci-artifacts"
mkdir -p "$ARTIFACT_DIR"

# Copy binary
BINARY_PATH="$OUTPUT_DIR"
if [[ "$BUILD_TYPE" == "release" ]]; then
    BINARY_PATH="$BINARY_PATH/release"
else
    BINARY_PATH="$BINARY_PATH/debug"
fi

if [[ -n "$TARGET" ]]; then
    BINARY_PATH="$OUTPUT_DIR/$TARGET/$BUILD_TYPE"
fi

if [[ -f "$BINARY_PATH/soliditydefend" ]]; then
    cp "$BINARY_PATH/soliditydefend" "$ARTIFACT_DIR/"
    green "✓ Binary copied to artifacts"
else
    red "✗ Binary not found at $BINARY_PATH/soliditydefend"
    exit 1
fi

# Copy additional files
if [[ -d "templates" ]]; then
    cp -r templates "$ARTIFACT_DIR/"
    green "✓ Templates copied to artifacts"
fi

# Generate build info
cat > "$ARTIFACT_DIR/build-info.json" << EOF
{
    "build_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "build_type": "$BUILD_TYPE",
    "ci_platform": "$CI_PLATFORM",
    "rust_version": "$(rustc --version)",
    "cargo_version": "$(cargo --version)",
    "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')",
    "git_branch": "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')",
    "target": "$TARGET",
    "features": "$FEATURES"
}
EOF
green "✓ Build info generated"

# Platform-specific artifact handling
case "$CI_PLATFORM" in
    github)
        # GitHub Actions artifact upload instructions
        echo "::set-output name=artifact-path::$ARTIFACT_DIR"
        echo "::set-output name=binary-path::$ARTIFACT_DIR/soliditydefend"
        ;;
    gitlab)
        # GitLab CI artifact paths
        echo "ARTIFACT_PATH=$ARTIFACT_DIR" >> build.env
        echo "BINARY_PATH=$ARTIFACT_DIR/soliditydefend" >> build.env
        ;;
esac

log_section "Build Summary"
echo "Build completed successfully!"
echo "Artifacts location: $ARTIFACT_DIR"
echo "Binary location: $ARTIFACT_DIR/soliditydefend"

# Verify binary works
if [[ -f "$ARTIFACT_DIR/soliditydefend" ]]; then
    blue "Testing binary..."
    if "$ARTIFACT_DIR/soliditydefend" --version &> /dev/null; then
        green "✓ Binary is functional"
    else
        yellow "⚠ Binary version check failed (may be expected)"
    fi
fi

green "🎉 CI build completed successfully!"