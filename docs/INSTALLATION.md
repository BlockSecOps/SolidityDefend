# Installation Guide

This guide provides detailed installation instructions for SolidityDefend on various platforms.

## Table of Contents

- [System Requirements](#system-requirements)
- [Installation Methods](#installation-methods)
  - [Binary Releases (Recommended)](#binary-releases-recommended)
  - [Using Docker](#using-docker)
  - [From Source](#from-source)
- [Verification](#verification)
- [Platform-Specific Instructions](#platform-specific-instructions)
- [Troubleshooting](#troubleshooting)

## System Requirements

### Minimum Requirements
- **OS**: Linux (x86_64, aarch64), macOS (x86_64, ARM64), or Windows 10+ (x86_64)
- **RAM**: 2GB minimum, 4GB+ recommended for large projects
- **Disk**: 500MB for installation, additional space for cache and analysis results
- **Rust**: 1.82.0 or later (only required for [building from source](#from-source) — pre-built binaries and Docker images require no Rust installation)

### Recommended Requirements
- **RAM**: 8GB+ for optimal performance on large codebases
- **CPU**: Multi-core processor for parallel analysis
- **SSD**: For faster cache operations and file I/O

## Installation Methods

### Binary Releases (Recommended)

Pre-built binaries are automatically compiled, stripped, and published by **GitHub Actions** on every tagged release. Each release includes SHA256 checksums (`SHA256SUMS.txt`) for integrity verification.

Download from the [releases page](https://github.com/BlockSecOps/SolidityDefend/releases/latest):

**Available platforms:**

| Platform | Archive | Built on |
|----------|---------|----------|
| Linux x86_64 | `soliditydefend-vX.X.X-linux-x86_64.tar.gz` | `ubuntu-latest` (native) |
| Linux aarch64 | `soliditydefend-vX.X.X-linux-aarch64.tar.gz` | `ubuntu-latest` via [`cross`](https://github.com/cross-rs/cross) |
| macOS ARM64 (Apple Silicon) | `soliditydefend-vX.X.X-macos-aarch64.tar.gz` | `macos-latest` (native arm64) |
| macOS Intel | `soliditydefend-vX.X.X-macos-x86_64.tar.gz` | `macos-latest` (cross-compile x86_64) |
| Windows x86_64 | `soliditydefend-vX.X.X-windows-x86_64.zip` | `windows-latest` (native) |

**Installation steps:**
1. Download the appropriate archive for your platform
2. Verify the checksum against `SHA256SUMS.txt`
3. Extract the binary: `tar -xzf soliditydefend-*.tar.gz` (or unzip for Windows)
4. Move to your PATH: `mv soliditydefend /usr/local/bin/` (or add to PATH on Windows)
5. Verify: `soliditydefend --version`

### Quick Install Script

The install script automates the above steps by downloading the latest release from GitHub:

```bash
curl -sSfL https://raw.githubusercontent.com/BlockSecOps/SolidityDefend/main/install.sh | bash
```

This script will:
- Automatically detect your platform (Linux, macOS, Windows)
- Download the latest pre-compiled binary from GitHub Releases
- Install it to `~/.local/bin` (or custom location via `INSTALL_DIR`)
- Verify the installation

**Custom installation directory:**
```bash
curl -sSfL https://raw.githubusercontent.com/BlockSecOps/SolidityDefend/main/install.sh | INSTALL_DIR=/usr/local/bin bash
```

### Using Homebrew (macOS and Linux)

```bash
# Add the tap (first time only)
brew tap BlockSecOps/tap

# Install SolidityDefend
brew install soliditydefend

# Update to latest version
brew upgrade soliditydefend
```

### From Source

Building from source is useful for development or if a pre-built binary is not available for your platform.

#### Prerequisites

1. **Install Rust** (if not already installed):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source ~/.cargo/env
   ```

2. **Verify Rust installation**:
   ```bash
   rustc --version
   # Should show version 1.82.0 or later
   ```

3. **Install Git** (if not already installed):
   - **Ubuntu/Debian**: `sudo apt-get install git`
   - **macOS**: `git` (comes with Xcode Command Line Tools)
   - **Windows**: Download from [git-scm.com](https://git-scm.com/download/win)

#### Build Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/BlockSecOps/SolidityDefend.git
   cd SolidityDefend
   ```

2. **Build the project**:
   ```bash
   # Release build (optimized, recommended)
   cargo build --release

   # Debug build (faster compilation, for development)
   cargo build
   ```

   > **Note**: Recent improvements have resolved major compilation issues in the detector pipeline. The build process now completes successfully with all core DeFi detectors functional.

3. **Install globally** (optional):
   ```bash
   cargo install --path crates/soliditydefend
   ```

4. **Verify installation**:
   ```bash
   # If installed globally
   soliditydefend --version

   # If using local build
   ./target/release/soliditydefend --version
   ```

#### Build Optimization

For maximum performance, build with additional optimizations:

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

### Using Docker

Multi-platform Docker images (`linux/amd64`, `linux/arm64`) are automatically built and published to **Docker Hub** by GitHub Actions on every tagged release.

#### Prerequisites

- **Docker**: Install from [docker.com](https://www.docker.com/get-started)
- **Docker Compose** (optional): For development workflows

#### Basic Docker Usage

1. **Pull the image from Docker Hub**:
   ```bash
   # Latest release
   docker pull blocksecops/soliditydefend:latest

   # Specific version
   docker pull blocksecops/soliditydefend:1.10.15
   ```

2. **Run analysis**:
   ```bash
   # Analyze files in current directory
   docker run --rm -v $(pwd):/workspace blocksecops/soliditydefend:latest /workspace/*.sol

   # With custom output
   docker run --rm -v $(pwd):/workspace blocksecops/soliditydefend:latest \
     -f json -o /workspace/results.json /workspace/contract.sol
   ```

3. **Or build locally from source** (for development):
   ```bash
   git clone https://github.com/BlockSecOps/SolidityDefend.git
   cd SolidityDefend
   docker build -t soliditydefend .
   ```

#### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'
services:
  soliditydefend:
    image: blocksecops/soliditydefend:latest
    volumes:
      - ./contracts:/workspace
    working_dir: /workspace
    command: ["--help"]
```

```bash
docker-compose run soliditydefend /workspace/*.sol
```

## Verification

### Test Installation

1. **Check version**:
   ```bash
   soliditydefend --version
   ```

2. **List detectors**:
   ```bash
   soliditydefend --list-detectors
   ```

3. **Run help**:
   ```bash
   soliditydefend --help
   ```

### Test Analysis

Create a simple test contract:

```solidity
// test.sol
pragma solidity ^0.8.0;

contract TestContract {
    function unsafeFunction() public {
        // This should trigger the default visibility detector
    }
}
```

Run analysis:
```bash
soliditydefend test.sol
```

Expected output should show detected issues.

## Platform-Specific Instructions

> **Note:** For most users, [pre-built binaries](#binary-releases-recommended) or [Docker](#using-docker) are the easiest installation methods. The instructions below are for building from source.

### Linux (Ubuntu/Debian)

1. **Install dependencies**:
   ```bash
   sudo apt-get update
   sudo apt-get install build-essential curl git
   ```

2. **Install Rust**:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source ~/.cargo/env
   ```

3. **Build and install**:
   ```bash
   git clone https://github.com/BlockSecOps/SolidityDefend.git
   cd SolidityDefend
   cargo build --release
   sudo cp target/release/soliditydefend /usr/local/bin/
   ```

### macOS

1. **Install Xcode Command Line Tools**:
   ```bash
   xcode-select --install
   ```

2. **Install Rust**:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source ~/.cargo/env
   ```

3. **Build and install**:
   ```bash
   git clone https://github.com/BlockSecOps/SolidityDefend.git
   cd SolidityDefend
   cargo build --release
   sudo cp target/release/soliditydefend /usr/local/bin/
   ```


### Windows

1. **Install Rust** using the installer from [rustup.rs](https://rustup.rs/)

2. **Install Git** from [git-scm.com](https://git-scm.com/download/win)

3. **Open PowerShell or Command Prompt** and run:
   ```cmd
   git clone https://github.com/BlockSecOps/SolidityDefend.git
   cd SolidityDefend
   cargo build --release
   ```

4. **Add to PATH** (optional):
   - Copy `target/release/soliditydefend.exe` to a directory in your PATH
   - Or add the target/release directory to your PATH environment variable

#### Using WSL (Windows Subsystem for Linux)

For better performance and compatibility, consider using WSL:

```bash
# In WSL
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
git clone https://github.com/BlockSecOps/SolidityDefend.git
cd SolidityDefend
cargo build --release
```

## Troubleshooting

### Common Issues

#### Build Fails with "linker not found"

**Solution**: Install build tools
- **Linux**: `sudo apt-get install build-essential`
- **macOS**: `xcode-select --install`
- **Windows**: Install Visual Studio Build Tools

#### Out of Memory During Build

**Solution**: Reduce parallel jobs
```bash
cargo build --release -j 2
```

#### Rust Version Too Old

**Solution**: Update Rust
```bash
rustup update stable
```

#### Permission Denied (Linux/macOS)

**Solution**: Use sudo for system installation or install to user directory
```bash
# Install to user directory
cargo install --path crates/soliditydefend --root ~/.local
export PATH="$HOME/.local/bin:$PATH"
```

### Performance Issues

#### Analysis is Slow

1. **Use release build**: Always use `--release` for production
2. **Increase memory**: Ensure sufficient RAM is available
3. **Use SSD storage**: For better cache performance
4. **Exclude large files**: Use file patterns to exclude unnecessary files

#### High Memory Usage

1. **Analyze smaller batches**: Process files in smaller groups
2. **Clear cache**: Remove cache files if they become too large
3. **Use streaming mode**: For very large files (when available)

### Getting Help

If you encounter issues not covered here:

1. **Check existing issues**: [GitHub Issues](https://github.com/BlockSecOps/SolidityDefend/issues)
2. **Create a new issue**: Include system info and error messages
3. **Community support**: Join our community channels
4. **Documentation**: Check other docs in the [docs/](.) directory

## Environment Configuration

### Environment Variables

SolidityDefend respects several environment variables:

```bash
# Cache directory (default: ~/.cache/soliditydefend)
export SOLIDITYDEFEND_CACHE_DIR=/custom/cache/path

# Log level (debug, info, warn, error)
export SOLIDITYDEFEND_LOG_LEVEL=info

# Maximum memory usage (in MB)
export SOLIDITYDEFEND_MAX_MEMORY=4096

# Number of parallel threads
export SOLIDITYDEFEND_THREADS=4
```

### Shell Integration

Add these aliases to your shell configuration:

```bash
# ~/.bashrc or ~/.zshrc
alias sd='soliditydefend'
alias sdj='soliditydefend -f json'
alias sdc='soliditydefend -f console'

# Function for quick analysis
analyze() {
    soliditydefend -f console "$@" | less -R
}
```

## Next Steps

After installation:

1. **Read the [Usage Guide](USAGE.md)** for examples and tutorials
2. **Check the [CLI Reference](CLI.md)** for all available options
3. **Configure your setup** using the [Configuration Guide](CONFIGURATION.md)
4. **Learn about detectors** in the [Detector Documentation](DETECTORS.md)

## Uninstallation

### Removing SolidityDefend

**If installed with cargo install**:
```bash
cargo uninstall soliditydefend
```

**If installed manually**:
```bash
# Remove binary
sudo rm /usr/local/bin/soliditydefend

# Remove cache (optional)
rm -rf ~/.cache/soliditydefend
```

**Docker cleanup**:
```bash
docker rmi blocksecops/soliditydefend:latest
docker system prune  # Remove unused containers and images
```