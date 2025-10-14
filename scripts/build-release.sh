#!/usr/bin/env bash
# Local Release Build Script for SolidityDefend
# Builds release binaries for all platforms locally

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

# Configuration
VERSION="${1:-$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')}"
BINARY_NAME="soliditydefend"
BUILD_DIR="target/release-builds"
RELEASE_DIR="releases/v${VERSION}"

info "Building SolidityDefend v${VERSION} for all platforms"
echo ""

# Create output directories
mkdir -p "${BUILD_DIR}"
mkdir -p "${RELEASE_DIR}"

# Detect host platform
HOST_OS=$(uname -s)
HOST_ARCH=$(uname -m)

info "Host platform: ${HOST_OS} ${HOST_ARCH}"
echo ""

# Function to build for a target
build_target() {
    local target=$1
    local platform_name=$2

    info "Building for ${platform_name} (${target})..."

    # Check if target is installed
    if ! rustup target list --installed | grep -q "${target}"; then
        info "Installing target ${target}..."
        rustup target add "${target}" || {
            warning "Failed to add target ${target}, skipping..."
            return 1
        }
    fi

    # Build
    if cargo build --release --target "${target}" --bin "${BINARY_NAME}"; then
        success "Built ${platform_name}"

        # Copy binary to build directory
        local binary_path="target/${target}/release/${BINARY_NAME}"
        if [ "${target}" = *"windows"* ] || [ -f "${binary_path}.exe" ]; then
            binary_path="${binary_path}.exe"
        fi

        if [ -f "${binary_path}" ]; then
            cp "${binary_path}" "${BUILD_DIR}/${BINARY_NAME}-${platform_name}"
            return 0
        else
            warning "Binary not found at ${binary_path}"
            return 1
        fi
    else
        warning "Build failed for ${platform_name}"
        return 1
    fi
}

# Build for current platform (guaranteed to work)
info "Building for current platform first..."
cargo build --release --bin "${BINARY_NAME}"
success "Current platform build complete"
echo ""

# Determine which platforms we can build for
info "Attempting cross-compilation for other platforms..."
echo ""

# Try to build for common targets
TARGETS_ATTEMPTED=0
TARGETS_SUCCESS=0

# macOS targets
if [ "${HOST_OS}" = "Darwin" ]; then
    info "Detected macOS host - building for macOS targets"

    if [ "${HOST_ARCH}" = "arm64" ]; then
        # Apple Silicon Mac
        build_target "aarch64-apple-darwin" "aarch64-apple-darwin" && ((TARGETS_SUCCESS++))
        ((TARGETS_ATTEMPTED++))

        # Try Intel Mac (may work with Rosetta)
        build_target "x86_64-apple-darwin" "x86_64-apple-darwin" && ((TARGETS_SUCCESS++))
        ((TARGETS_ATTEMPTED++))
    else
        # Intel Mac
        build_target "x86_64-apple-darwin" "x86_64-apple-darwin" && ((TARGETS_SUCCESS++))
        ((TARGETS_ATTEMPTED++))

        # Try Apple Silicon (requires Xcode 12.2+)
        build_target "aarch64-apple-darwin" "aarch64-apple-darwin" && ((TARGETS_SUCCESS++))
        ((TARGETS_ATTEMPTED++))
    fi
fi

# Linux targets (if on Linux)
if [ "${HOST_OS}" = "Linux" ]; then
    info "Detected Linux host - building for Linux targets"

    build_target "x86_64-unknown-linux-gnu" "x86_64-unknown-linux-gnu" && ((TARGETS_SUCCESS++))
    ((TARGETS_ATTEMPTED++))

    # ARM64 Linux (requires cross-compilation tools)
    if command -v cross &> /dev/null; then
        info "Using cross for ARM64 build"
        cross build --release --target aarch64-unknown-linux-gnu --bin "${BINARY_NAME}" && {
            cp "target/aarch64-unknown-linux-gnu/release/${BINARY_NAME}" "${BUILD_DIR}/${BINARY_NAME}-aarch64-unknown-linux-gnu"
            success "Built aarch64-unknown-linux-gnu"
            ((TARGETS_SUCCESS++))
        }
        ((TARGETS_ATTEMPTED++))
    fi
fi

echo ""
info "Build Summary:"
echo "  Attempted: ${TARGETS_ATTEMPTED} cross-compilation targets"
echo "  Successful: ${TARGETS_SUCCESS} targets"
echo ""

# Copy current platform binary
CURRENT_BINARY="target/release/${BINARY_NAME}"
if [ -f "${CURRENT_BINARY}" ]; then
    # Determine current platform name
    case "${HOST_OS}-${HOST_ARCH}" in
        Darwin-arm64)
            CURRENT_PLATFORM="aarch64-apple-darwin"
            ;;
        Darwin-x86_64)
            CURRENT_PLATFORM="x86_64-apple-darwin"
            ;;
        Linux-x86_64)
            CURRENT_PLATFORM="x86_64-unknown-linux-gnu"
            ;;
        Linux-aarch64)
            CURRENT_PLATFORM="aarch64-unknown-linux-gnu"
            ;;
        *)
            CURRENT_PLATFORM="unknown"
            ;;
    esac

    cp "${CURRENT_BINARY}" "${BUILD_DIR}/${BINARY_NAME}-${CURRENT_PLATFORM}"
    success "Copied current platform binary: ${CURRENT_PLATFORM}"
fi

echo ""
info "Built binaries available in: ${BUILD_DIR}/"
ls -lh "${BUILD_DIR}/"

echo ""
success "Build process complete!"
echo ""
warning "Note: Cross-compilation may not work for all platforms from your host."
warning "For missing platforms, you'll need to build on that platform or use Docker."
echo ""
info "Next steps:"
echo "  1. Test binaries: ${BUILD_DIR}/${BINARY_NAME}-*"
echo "  2. Create release: ./scripts/create-release.sh ${VERSION}"
