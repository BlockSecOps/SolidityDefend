# Configuration Guide

This guide covers all configuration options for SolidityDefend, including environment variables, configuration files, and advanced settings.

## Table of Contents

- [Configuration Methods](#configuration-methods)
- [Environment Variables](#environment-variables)
- [Configuration Files](#configuration-files)
- [Cache Configuration](#cache-configuration)
- [Performance Tuning](#performance-tuning)
- [Detector Configuration](#detector-configuration)
- [Output Configuration](#output-configuration)
- [Logging Configuration](#logging-configuration)
- [Advanced Settings](#advanced-settings)

## Configuration Methods

SolidityDefend can be configured through multiple methods, listed in order of precedence:

1. **Command-line arguments** (highest priority)
2. **Environment variables**
3. **Configuration files** (YAML format)
4. **Default values** (lowest priority)

## Environment Variables

### Cache Configuration

#### `SOLIDITYDEFEND_CACHE_DIR`
**Default:** `~/.cache/soliditydefend` (Linux/macOS), `%LOCALAPPDATA%\soliditydefend\cache` (Windows)

Directory where analysis cache is stored.

```bash
export SOLIDITYDEFEND_CACHE_DIR=/tmp/sd-cache
```

#### `SOLIDITYDEFEND_CACHE_SIZE`
**Default:** `1024` (MB)

Maximum cache size in megabytes. When exceeded, oldest entries are evicted.

```bash
export SOLIDITYDEFEND_CACHE_SIZE=2048  # 2GB cache
```

#### `SOLIDITYDEFEND_CACHE_DISABLE`
**Default:** `false`

Disable caching entirely. Useful for debugging or CI environments.

```bash
export SOLIDITYDEFEND_CACHE_DISABLE=true
```

### Performance Configuration

#### `SOLIDITYDEFEND_MAX_MEMORY`
**Default:** `4096` (MB)

Maximum memory usage in megabytes. Analysis will be throttled if this limit is approached.

```bash
export SOLIDITYDEFEND_MAX_MEMORY=8192  # 8GB limit
```

#### `SOLIDITYDEFEND_THREADS`
**Default:** Number of CPU cores

Number of threads to use for parallel analysis.

```bash
export SOLIDITYDEFEND_THREADS=8        # Use 8 threads
export SOLIDITYDEFEND_THREADS=1        # Single-threaded mode
```

#### `SOLIDITYDEFEND_TIMEOUT`
**Default:** `300` (seconds)

Timeout for analyzing a single file in seconds.

```bash
export SOLIDITYDEFEND_TIMEOUT=600      # 10 minute timeout
```

### Output Configuration

#### `NO_COLOR`
Disable colored output when set to any value.

```bash
export NO_COLOR=1
soliditydefend contract.sol  # No colors
```

#### `CLICOLOR_FORCE`
Force colored output even when not in a terminal.

```bash
export CLICOLOR_FORCE=1
soliditydefend contract.sol | less -R  # Colors in pager
```

#### `SOLIDITYDEFEND_OUTPUT_WIDTH`
**Default:** Terminal width or `80`

Maximum width for console output formatting.

```bash
export SOLIDITYDEFEND_OUTPUT_WIDTH=120
```

### Logging Configuration

#### `RUST_LOG`
Standard Rust logging configuration. Supports complex filtering.

```bash
# Debug everything
export RUST_LOG=debug

# Info level for SolidityDefend only
export RUST_LOG=soliditydefend=info

# Multiple modules with different levels
export RUST_LOG=soliditydefend=debug,solang_parser=warn

# Trace specific detector
export RUST_LOG=soliditydefend::detectors::reentrancy=trace
```

#### `SOLIDITYDEFEND_LOG_LEVEL`
**Default:** `info`

Simplified logging level configuration.

```bash
export SOLIDITYDEFEND_LOG_LEVEL=debug   # Enable debug logging
export SOLIDITYDEFEND_LOG_LEVEL=warn    # Only warnings and errors
export SOLIDITYDEFEND_LOG_LEVEL=error   # Only errors
```

#### `SOLIDITYDEFEND_LOG_FILE`
**Default:** Not set (log to stderr)

Log file path. If not set, logs go to stderr.

```bash
export SOLIDITYDEFEND_LOG_FILE=/var/log/soliditydefend.log
```

## Configuration Files

SolidityDefend supports YAML configuration files for comprehensive customization. Configuration files are loaded in the following order:

1. File specified with `--config` option
2. `.soliditydefend.yml` in current directory
3. `.soliditydefend.yaml` in current directory
4. `~/.config/soliditydefend/config.yml` (user config)
5. `~/.soliditydefend.yml` (user config)

### Creating Configuration Files

Use the `--init-config` flag to create a default configuration file:

```bash
# Create .soliditydefend.yml in current directory
soliditydefend --init-config

# Use custom configuration file
soliditydefend --config my-config.yml contracts/
```

### Configuration File Format

**Example: `.soliditydefend.yml`**

```yaml
# General analysis settings
general:
  min_severity: Info              # Minimum severity to report
  verbose: false                  # Enable verbose logging
  quiet: false                   # Enable quiet mode
  include_patterns:              # File patterns to include
    - "**/*.sol"
  exclude_patterns:              # File patterns to exclude
    - "**/node_modules/**"
    - "**/test/**"
    - "**/tests/**"
    - "**/.git/**"
  max_file_size: 10485760        # Max file size in bytes (10MB)

# Detector configuration
detectors:
  min_severity: Info             # Minimum detector severity
  min_confidence: Low            # Minimum confidence level
  enabled_categories: []         # Specific categories to enable (empty = all)
  disabled_detectors: []         # Specific detectors to disable
  enabled_detectors: []          # Specific detectors to enable (overrides disabled)
  detector_timeout: 30           # Timeout per detector in seconds
  fail_fast: false              # Stop on first critical finding
  custom_settings: {}           # Detector-specific settings

# Cache configuration
cache:
  enabled: true                  # Enable analysis caching
  max_memory_mb: 256            # Maximum memory usage
  max_entries: 10000            # Maximum cache entries
  cache_dir: null               # Custom cache directory (null = auto)
  persistent: true              # Enable persistent cache
  ttl_hours: 1                  # Cache time-to-live

# Output configuration
output:
  format: console               # Output format: console | json
  colors: true                  # Enable colored output
  show_fixes: true              # Show fix suggestions
  show_snippets: true           # Show code snippets
  snippet_lines: 3              # Lines to show in snippets
  sort_by_severity: true        # Sort findings by severity

# Performance settings
performance:
  max_threads: 8                # Maximum parallel threads
  parallel_analysis: true       # Enable parallel processing
  batch_size: 10               # Files per batch
  memory_limit_mb: 512         # Memory limit per analysis
```

### Detector Categories

Available detector categories for the `enabled_categories` setting:

- `AccessControl` - Access control and authorization issues
- `Reentrancy` - Reentrancy vulnerabilities
- `ReentrancyAttacks` - Reentrancy attack patterns
- `Oracle` - Oracle manipulation and price attacks
- `FlashLoan` - Flash loan attack vectors
- `FlashLoanAttacks` - Flash loan attack patterns
- `MEV` - MEV and front-running issues
- `ExternalCalls` - External call vulnerabilities
- `Validation` - Input validation problems
- `Logic` - Logic bugs and business logic issues
- `Timestamp` - Timestamp dependencies
- `Auth` - Authentication and authorization
- `BestPractices` - General security best practices

### Project-Specific Configuration

Create a `.soliditydefend.yml` in your project root:

```yaml
general:
  min_severity: Medium
  exclude_patterns:
    - "**/node_modules/**"
    - "**/test/**"
    - "**/mock/**"
    - "**/migrations/**"

detectors:
  min_confidence: Medium
  enabled_categories:
    - AccessControl
    - Reentrancy
    - Oracle
    - FlashLoan
  disabled_detectors:
    - parameter-consistency    # Too noisy for this project

output:
  format: json
  show_fixes: true
  sort_by_severity: true

performance:
  max_threads: 4
  parallel_analysis: true
```

## Cache Configuration

### Cache Location

```bash
# Default locations by platform
# Linux: ~/.cache/soliditydefend/
# macOS: ~/Library/Caches/soliditydefend/
# Windows: %LOCALAPPDATA%\soliditydefend\cache\

# Custom location
export SOLIDITYDEFEND_CACHE_DIR=/opt/soliditydefend-cache
```

### Cache Management

```bash
# Check cache size
du -sh ~/.cache/soliditydefend/

# Clear cache
rm -rf ~/.cache/soliditydefend/

# Disable cache for one run
SOLIDITYDEFEND_CACHE_DISABLE=true soliditydefend contract.sol

# Set cache size limit
export SOLIDITYDEFEND_CACHE_SIZE=512  # 512MB limit
```

### Cache Structure

```
~/.cache/soliditydefend/
├── analysis/           # Analysis results cache
│   ├── <hash>.json    # Cached analysis results
│   └── index.db       # Cache index
├── ast/               # Parsed AST cache
│   └── <hash>.ast     # Cached AST representations
└── metadata.json      # Cache metadata
```

## Performance Tuning

### Memory Configuration

```bash
# For small projects (< 100 files)
export SOLIDITYDEFEND_MAX_MEMORY=1024    # 1GB
export SOLIDITYDEFEND_THREADS=2

# For medium projects (100-1000 files)
export SOLIDITYDEFEND_MAX_MEMORY=4096    # 4GB (default)
export SOLIDITYDEFEND_THREADS=4

# For large projects (1000+ files)
export SOLIDITYDEFEND_MAX_MEMORY=8192    # 8GB
export SOLIDITYDEFEND_THREADS=8
```

### Analysis Optimization

```bash
# Faster analysis (less thorough)
export SOLIDITYDEFEND_ANALYSIS_DEPTH=shallow
export SOLIDITYDEFEND_TIMEOUT=60

# Thorough analysis (slower)
export SOLIDITYDEFEND_ANALYSIS_DEPTH=deep
export SOLIDITYDEFEND_TIMEOUT=600

# Incremental analysis (future)
export SOLIDITYDEFEND_INCREMENTAL=true
```

### Parallel Processing

```bash
# Optimal thread count = CPU cores
export SOLIDITYDEFEND_THREADS=$(nproc)

# Conservative (for shared systems)
export SOLIDITYDEFEND_THREADS=$(($(nproc) / 2))

# Single-threaded (debugging)
export SOLIDITYDEFEND_THREADS=1
```

## Detector Configuration

### Enabling/Disabling Detectors

As of v1.10.23, all **67 detectors are enabled by default** and precision-tuned (18.4% precision, 100% recall). Use the YAML config to control which detectors run:

```yaml
# .soliditydefend.yml
detectors:
  disabled_detectors:
    - parameter-consistency     # Disable an additional detector
  enabled_detectors:
    - timestamp-manipulation    # Re-enable a default-disabled detector
```

The `enabled_detectors` list takes precedence over `disabled_detectors` and the built-in `DEFAULT_DISABLED` list. This allows re-enabling specific detectors that are disabled by default.

```bash
# List all available detectors (including disabled)
soliditydefend --list-detectors
```

### Detector Sensitivity

```bash
# Strict mode (more sensitive)
export SOLIDITYDEFEND_STRICT_MODE=true

# Relaxed mode (fewer false positives)
export SOLIDITYDEFEND_STRICT_MODE=false
```

### Custom Severity Levels

```bash
# Future feature: Override detector severities
export SOLIDITYDEFEND_SEVERITY_OVERRIDES="parameter-consistency=info,gas-limit=low"
```

## Output Configuration

### Format Defaults

```bash
# Set default output format
export SOLIDITYDEFEND_DEFAULT_FORMAT=json

# Always output to file
export SOLIDITYDEFEND_DEFAULT_OUTPUT=security-report.json
```

### Console Customization

```bash
# Disable code snippets
export SOLIDITYDEFEND_NO_SNIPPETS=true

# Compact output
export SOLIDITYDEFEND_COMPACT=true

# Show file paths relative to current directory
export SOLIDITYDEFEND_RELATIVE_PATHS=true

# Maximum number of issues to display
export SOLIDITYDEFEND_MAX_DISPLAY=50
```

### JSON Output Options

```bash
# Pretty-print JSON
export SOLIDITYDEFEND_JSON_PRETTY=true

# Include code snippets in JSON
export SOLIDITYDEFEND_JSON_SNIPPETS=true

# Include fix suggestions
export SOLIDITYDEFEND_JSON_FIXES=true
```

## Logging Configuration

### Log Levels

```bash
# Trace: Very verbose debugging
export RUST_LOG=trace

# Debug: Detailed debugging information
export RUST_LOG=debug

# Info: General information (default)
export RUST_LOG=info

# Warn: Warnings only
export RUST_LOG=warn

# Error: Errors only
export RUST_LOG=error
```

### Module-Specific Logging

```bash
# Enable debug for specific modules
export RUST_LOG=soliditydefend::detectors=debug,soliditydefend::parser=info

# Trace specific detector
export RUST_LOG=soliditydefend::detectors::reentrancy=trace

# Disable noisy modules
export RUST_LOG=soliditydefend=info,solang_parser=warn
```

### Log Output

```bash
# Log to file
export SOLIDITYDEFEND_LOG_FILE=/var/log/soliditydefend.log

# Log with timestamps
export RUST_LOG_STYLE=always

# Structured logging (JSON)
export SOLIDITYDEFEND_LOG_FORMAT=json
```

## Advanced Settings

### Analysis Behavior

```bash
# Continue analysis on parse errors
export SOLIDITYDEFEND_CONTINUE_ON_ERROR=true

# Maximum file size to analyze (in MB)
export SOLIDITYDEFEND_MAX_FILE_SIZE=10

# Skip files matching patterns
export SOLIDITYDEFEND_EXCLUDE_PATTERNS="test/**,mock/**,node_modules/**"

# Include hidden files
export SOLIDITYDEFEND_INCLUDE_HIDDEN=true
```

### Network Configuration

```bash
# HTTP proxy for future features
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080

# Timeout for network operations
export SOLIDITYDEFEND_NETWORK_TIMEOUT=30
```

### Development Settings

```bash
# Enable experimental features
export SOLIDITYDEFEND_EXPERIMENTAL=true

# Debug AST output
export SOLIDITYDEFEND_DEBUG_AST=true

# Profile analysis performance
export SOLIDITYDEFEND_PROFILE=true

# Dump intermediate representations
export SOLIDITYDEFEND_DUMP_IR=true
```

## Platform-Specific Configuration

### Linux

```bash
# System-wide configuration
sudo tee /etc/environment <<EOF
SOLIDITYDEFEND_CACHE_DIR=/var/cache/soliditydefend
SOLIDITYDEFEND_MAX_MEMORY=8192
EOF

# User configuration
echo 'export SOLIDITYDEFEND_THREADS=8' >> ~/.bashrc
```

### macOS

```bash
# User configuration
echo 'export SOLIDITYDEFEND_CACHE_DIR=$HOME/Library/Caches/SolidityDefend' >> ~/.zshrc

# Homebrew-style configuration (future)
export SOLIDITYDEFEND_CONFIG_DIR=/opt/homebrew/etc/soliditydefend
```

### Windows

```cmd
REM System-wide configuration
setx SOLIDITYDEFEND_CACHE_DIR "C:\ProgramData\SolidityDefend\Cache" /M
setx SOLIDITYDEFEND_MAX_MEMORY "4096" /M

REM User configuration
setx SOLIDITYDEFEND_THREADS "4"
```

```powershell
# PowerShell configuration
$env:SOLIDITYDEFEND_CACHE_DIR = "$env:LOCALAPPDATA\SolidityDefend\Cache"
[Environment]::SetEnvironmentVariable("SOLIDITYDEFEND_CACHE_DIR", $env:SOLIDITYDEFEND_CACHE_DIR, "User")
```

## Configuration Examples

### CI/CD Configuration

```bash
# GitHub Actions / GitLab CI
export SOLIDITYDEFEND_CACHE_DISABLE=true    # Disable cache in CI
export SOLIDITYDEFEND_THREADS=2             # Limited resources
export SOLIDITYDEFEND_MAX_MEMORY=2048       # 2GB limit
export NO_COLOR=1                           # No colors in CI logs
export SOLIDITYDEFEND_LOG_LEVEL=warn        # Reduce log noise
```

### Development Environment

```bash
# ~/.bashrc or ~/.zshrc
export SOLIDITYDEFEND_CACHE_DIR="$HOME/.cache/soliditydefend"
export SOLIDITYDEFEND_MAX_MEMORY=8192
export SOLIDITYDEFEND_THREADS=8
export RUST_LOG=soliditydefend=info
export SOLIDITYDEFEND_JSON_PRETTY=true
```

### Production Analysis

```bash
# High-performance production analysis
export SOLIDITYDEFEND_MAX_MEMORY=16384      # 16GB
export SOLIDITYDEFEND_THREADS=16            # All cores
export SOLIDITYDEFEND_CACHE_SIZE=4096       # 4GB cache
export SOLIDITYDEFEND_TIMEOUT=1800          # 30 minute timeout
export SOLIDITYDEFEND_LOG_FILE=/var/log/soliditydefend.log
```

### Docker Configuration

```dockerfile
# Dockerfile environment variables
ENV SOLIDITYDEFEND_CACHE_DIR=/app/cache
ENV SOLIDITYDEFEND_MAX_MEMORY=2048
ENV SOLIDITYDEFEND_THREADS=4
ENV NO_COLOR=1
```

```yaml
# docker-compose.yml
services:
  soliditydefend:
    image: soliditydefend:latest
    environment:
      - SOLIDITYDEFEND_CACHE_DIR=/cache
      - SOLIDITYDEFEND_MAX_MEMORY=4096
      - SOLIDITYDEFEND_THREADS=8
    volumes:
      - ./contracts:/workspace
      - cache-volume:/cache
```

## Troubleshooting Configuration

### Check Current Configuration

```bash
# Show all environment variables
env | grep SOLIDITYDEFEND

# Test configuration
RUST_LOG=debug soliditydefend --help 2>&1 | head -20
```

### Reset to Defaults

```bash
# Clear all SolidityDefend environment variables
unset $(env | grep '^SOLIDITYDEFEND' | cut -d= -f1)

# Clear cache
rm -rf ~/.cache/soliditydefend/
```

### Validate Configuration

```bash
# Check memory limit
echo "Memory limit: $SOLIDITYDEFEND_MAX_MEMORY MB"

# Check thread count
echo "Threads: ${SOLIDITYDEFEND_THREADS:-auto}"

# Check cache location
echo "Cache: ${SOLIDITYDEFEND_CACHE_DIR:-~/.cache/soliditydefend}"

# Test configuration with dry run (future feature)
soliditydefend --dry-run --show-config
```

## Future Configuration Features

The following configuration options are planned for future releases:

- **Custom rule definitions**
- **Integration with external tools**
- **Team/organization-wide configuration**
- **Configuration validation and migration**

## See Also

- [CLI Reference](CLI.md) - Command-line options
- [Usage Guide](USAGE.md) - Usage examples with configuration
- [Installation Guide](INSTALLATION.md) - Installation and setup
- [Performance Guide](PERFORMANCE.md) - Performance optimization (future)
- [Detector Documentation](DETECTORS.md) - Available detectors