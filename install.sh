#!/usr/bin/env bash
# SolidityDefend Installation Script
# Installs the latest release of SolidityDefend from GitHub

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="SolidityOps/SolidityDefend"
BINARY_NAME="soliditydefend"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${VERSION:-latest}"

# Helper functions
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Detect OS and architecture
detect_platform() {
    local os
    local arch

    # Detect OS
    case "$(uname -s)" in
        Linux*)
            os="unknown-linux-gnu"
            ;;
        Darwin*)
            os="apple-darwin"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            os="pc-windows-msvc"
            ;;
        *)
            error "Unsupported operating system: $(uname -s)"
            ;;
    esac

    # Detect architecture
    case "$(uname -m)" in
        x86_64|amd64)
            arch="x86_64"
            ;;
        aarch64|arm64)
            arch="aarch64"
            ;;
        *)
            error "Unsupported architecture: $(uname -m)"
            ;;
    esac

    echo "${arch}-${os}"
}

# Get the latest release version from GitHub
get_latest_version() {
    if [ "$VERSION" = "latest" ]; then
        info "Fetching latest version from GitHub..."
        local latest_version
        latest_version=$(curl -sSf https://api.github.com/repos/${REPO}/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

        if [ -z "$latest_version" ]; then
            error "Failed to fetch latest version"
        fi

        echo "$latest_version"
    else
        echo "$VERSION"
    fi
}

# Download and install binary
install_binary() {
    local platform="$1"
    local version="$2"
    local download_url="https://github.com/${REPO}/releases/download/${version}/${BINARY_NAME}-${version}-${platform}.tar.gz"
    local temp_dir
    temp_dir=$(mktemp -d)

    info "Downloading SolidityDefend ${version} for ${platform}..."

    if ! curl -sSfL "$download_url" -o "${temp_dir}/${BINARY_NAME}.tar.gz"; then
        error "Failed to download from ${download_url}"
    fi

    info "Extracting binary..."
    tar -xzf "${temp_dir}/${BINARY_NAME}.tar.gz" -C "${temp_dir}"

    # Create install directory if it doesn't exist
    mkdir -p "$INSTALL_DIR"

    info "Installing to ${INSTALL_DIR}..."
    mv "${temp_dir}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

    # Clean up
    rm -rf "$temp_dir"

    success "SolidityDefend ${version} installed successfully!"
}

# Verify installation
verify_installation() {
    if command -v "$BINARY_NAME" &> /dev/null; then
        success "Verification successful!"
        info "Installed version: $($BINARY_NAME --version)"
    elif [ -x "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        success "Binary installed at ${INSTALL_DIR}/${BINARY_NAME}"
        warning "${INSTALL_DIR} is not in your PATH"
        info "Add it to your PATH by adding this to your ~/.bashrc or ~/.zshrc:"
        echo ""
        echo "    export PATH=\"\$PATH:${INSTALL_DIR}\""
        echo ""
    else
        error "Installation verification failed"
    fi
}

# Check for required tools
check_requirements() {
    if ! command -v curl &> /dev/null; then
        error "curl is required but not installed. Please install curl and try again."
    fi

    if ! command -v tar &> /dev/null; then
        error "tar is required but not installed. Please install tar and try again."
    fi
}

# Main installation flow
main() {
    echo ""
    info "SolidityDefend Installer"
    echo "========================"
    echo ""

    # Check requirements
    check_requirements

    # Detect platform
    local platform
    platform=$(detect_platform)
    info "Detected platform: ${platform}"

    # Get version
    local version
    version=$(get_latest_version)
    info "Installing version: ${version}"

    # Install
    install_binary "$platform" "$version"

    # Verify
    verify_installation

    echo ""
    info "Quick start:"
    echo "  ${BINARY_NAME} --help              # Show help"
    echo "  ${BINARY_NAME} --list-detectors    # List all detectors"
    echo "  ${BINARY_NAME} contract.sol        # Analyze a contract"
    echo ""
    success "Installation complete! 🎉"
}

# Run main function
main "$@"
