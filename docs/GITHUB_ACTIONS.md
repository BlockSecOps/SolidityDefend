# GitHub Actions CI/CD

This document describes the GitHub Actions workflows configured for SolidityDefend and how to test them locally.

## Workflows

### CI/CD Pipeline (`.github/workflows/ci.yml`)

**Triggers:** Push to `main` or `develop`, Pull Requests to `main`

**Jobs:**

1. **Build and Test**
   - Install Rust toolchain (stable)
   - Run code formatting checks (`cargo fmt`)
   - Run clippy linter (advisory mode — reports warnings but does not fail the build)
   - Build in debug and release modes
   - Run all tests
   - Verify detector count (333+ expected)
   - Upload build artifacts

2. **Docker Build** *(pushes to `main` only — skipped on PRs)*
   - Build Docker image
   - Test Docker image functionality

3. **Security Scan (Self-Test)**
   - Download build artifacts
   - Scan test contracts with SolidityDefend
   - Upload security report

4. **Code Coverage**
   - Generate code coverage using `cargo-llvm-cov`
   - Upload to Codecov (on push events)

### Release Pipeline (`.github/workflows/release.yml`)

**Triggers:** Git tags matching `v*`

**Architecture:** 3-job pipeline: `build-release` → `create-release` → `publish-docker`

**Jobs:**

1. **Build Release** (Matrix Strategy — 5 targets)

   | Runner | Target | Strategy |
   |--------|--------|----------|
   | `ubuntu-latest` | `x86_64-unknown-linux-gnu` | Native build |
   | `ubuntu-latest` | `aarch64-unknown-linux-gnu` | `cross` tool (Cross.toml) |
   | `macos-latest` | `aarch64-apple-darwin` | Native (arm64 runner) |
   | `macos-latest` | `x86_64-apple-darwin` | Cross-compile (arm64 runner) |
   | `windows-latest` | `x86_64-pc-windows-msvc` | Native build |

   Each target:
   - Builds the release binary (using `cross` for Linux aarch64, native `cargo` otherwise)
   - Strips the binary (Unix targets)
   - Packages into `.tar.gz` (Unix) or `.zip` (Windows)
   - Uploads as a GitHub Actions artifact

2. **Create Release** (needs: build-release)
   - Downloads all build artifacts
   - Generates `SHA256SUMS.txt` with checksums for all binaries
   - Extracts release notes from `CHANGELOG.md` for the tagged version
   - Creates the GitHub Release using `softprops/action-gh-release@v2`
   - Attaches all binaries and the checksums file

3. **Publish Docker** (needs: create-release)
   - Builds multi-platform Docker image (`linux/amd64`, `linux/arm64`)
   - Pushes to Docker Hub with version tag and `latest` tag
   - Includes OCI image labels and build-args

**Runner Compatibility Notes:**
- `macos-latest` is **arm64** (Apple Silicon) — Intel x86_64 builds cross-compile via `--target x86_64-apple-darwin`
- `macos-13` runners are **retired** — do not use
- `ubuntu-latest` is Ubuntu 22.04
- `windows-latest` is Windows Server 2022

### Detector Validation (`.github/workflows/validate.yml`)

**Triggers:** PRs and pushes modifying `crates/detectors/**` or `tests/validation/**`, manual dispatch

**Jobs:**

1. **Validate Detectors**
   - Builds release binary
   - Runs validation suite against ground truth
   - Reports precision, recall, and F1 score
   - Comments results on PRs

2. **Regression Tests**
   - Runs detector regression test suite

## Local Testing with `act`

### Prerequisites

```bash
# Install act (macOS)
brew install act

# Or install via Go
go install github.com/nektos/act@latest
```

### Configuration

The project includes `.actrc` with optimal settings:

```
-P ubuntu-latest=catthehacker/ubuntu:act-latest
--verbose
--container-daemon-socket /var/run/docker.sock
--env CARGO_TERM_COLOR=always
--env RUST_BACKTRACE=1
```

### Running Workflows Locally

#### List Available Workflows

```bash
act -l
```

Output:
```
Stage  Job ID          Job name                   Workflow name   Events
0      build-and-test  Build and Test            CI/CD Pipeline  push,pull_request
0      docker-build    Docker Build              CI/CD Pipeline  push,pull_request
0      coverage        Code Coverage             CI/CD Pipeline  push,pull_request
1      security-scan   Security Scan (Self-Test) CI/CD Pipeline  push,pull_request
```

#### Dry Run (Validate Workflow)

```bash
# Test the build-and-test job
act -n -j build-and-test

# Test specific workflow
act -n -W .github/workflows/ci.yml
```

#### Run Specific Job

```bash
# Run build-and-test job
act -j build-and-test

# Run docker-build job
act -j docker-build

# Run on pull_request event
act pull_request -j build-and-test
```

#### Run All Jobs

```bash
# Run all jobs for push event
act push

# Run all jobs for pull_request event
act pull_request
```

### Performance Considerations

**Full CI Pipeline Runtime:**
- Build and Test: ~10-15 minutes (includes Rust compilation)
- Docker Build: ~5-8 minutes
- Coverage: ~12-18 minutes
- Security Scan: ~2-3 minutes

**Resource Requirements:**
- Docker with ~8GB RAM recommended
- ~20GB free disk space (for build caches)
- Fast internet connection (first run downloads images)

### Caching

Act uses Docker layer caching and Rust cargo caching:

```yaml
- uses: actions-rust-lang/setup-rust-toolchain@v1
  with:
    toolchain: stable
    cache: true  # Enables cargo caching
```

**Cache Location:** `/Users/pwner/.cache/act/`

**Clear Cache:**
```bash
# Clear all act caches
rm -rf ~/.cache/act/

# Clear specific action cache
rm -rf ~/.cache/act/actions-rust-lang-setup-rust-toolchain@v1
```

## Workflow Details

### Environment Variables

Set globally in workflows:

```yaml
env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1
```

### Artifacts

**Build Artifacts:**
- Binary: `soliditydefend-linux-x86_64`
- Retention: 7 days

**Release Artifacts:**
- Per-target binaries (5 platforms)
- `SHA256SUMS.txt` with checksums
- Retention: 1 day (consumed by create-release job)

**Security Report:**
- File: `security-report.json`
- Retention: 30 days

### Secrets Required (for full CI/CD)

For release workflows, configure these secrets in GitHub:

- `DOCKER_USERNAME` - Docker Hub username
- `DOCKER_PASSWORD` - Docker Hub access token
- `GITHUB_TOKEN` - Automatically provided by GitHub Actions

## Debugging

### Enable Debug Logging

```bash
# Run with debug output
act -j build-and-test --verbose

# Run with secrets (for testing)
act -j build-and-test -s GITHUB_TOKEN=xxx
```

### Common Issues

**1. Docker Permission Denied**
```bash
# Add user to docker group (Linux)
sudo usermod -aG docker $USER
newgrp docker
```

**2. Out of Disk Space**
```bash
# Clean Docker
docker system prune -a

# Clean act cache
rm -rf ~/.cache/act/
```

**3. Rust Toolchain Installation Fails**

Check `.actrc` settings and ensure Docker has internet access.

## Integration with GitHub

### Branch Protection Rules

Recommended settings for `main` branch:

- Require status checks to pass
  - `build-and-test`
- Require branches to be up to date
- Require linear history
- Include administrators

### Pull Request Checks

All PRs to `main` automatically run:
1. Format checking
2. Linting (clippy — advisory mode, does not block builds)
3. Tests
4. Security scan

Note: Docker build is skipped on PRs (runs only on pushes to `main`).

## Continuous Deployment

### Automatic Releases

Create a release by pushing a tag:

```bash
# Tag the release
git tag -a v1.10.15 -m "Release v1.10.15"
git push origin v1.10.15
```

This triggers:
1. Multi-platform binary builds (5 targets)
2. Binary stripping and packaging
3. SHA256 checksum generation
4. Release creation with changelog notes
5. Docker image publication

### Manual Workflow Dispatch

Workflows can be manually triggered from GitHub Actions tab:

1. Go to Actions -> Select workflow
2. Click "Run workflow"
3. Select branch
4. Run

## Performance Optimization

### Parallelization

The CI pipeline runs jobs in parallel when possible:

```
Stage 0 (Parallel):
├── build-and-test
├── docker-build (main pushes only)
└── coverage

Stage 1 (Sequential):
└── security-scan (needs: build-and-test)
```

The release pipeline:

```
Stage 0 (Parallel matrix):
└── build-release (5 targets in parallel)

Stage 1:
└── create-release (needs: build-release)

Stage 2:
└── publish-docker (needs: create-release)
```

### Caching Strategy

1. **Rust Dependencies:** Cached by `actions-rust-lang/setup-rust-toolchain`
2. **Cargo Build:** Cached in `~/.cargo` and `target/`
3. **Docker Layers:** Cached by BuildKit

## Monitoring

### View Workflow Runs

```bash
# List recent workflow runs
gh run list

# View specific run
gh run view <run-id>

# Watch live run
gh run watch
```

### Artifacts

```bash
# Download artifacts
gh run download <run-id>

# List artifacts
gh run view <run-id> --log
```

## Best Practices

1. **Always run `act -n` (dry run) before pushing workflow changes**
2. **Test locally with `act` to catch issues early**
3. **Keep workflows modular** - separate jobs for different concerns
4. **Use caching** - significantly speeds up builds
5. **Pin action versions** - use `@v4` not `@latest` for stability

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [act GitHub Repository](https://github.com/nektos/act)
- [Rust Toolchain Action](https://github.com/actions-rust-lang/setup-rust-toolchain)
- [Docker Buildx Action](https://github.com/docker/setup-buildx-action)
- [softprops/action-gh-release](https://github.com/softprops/action-gh-release)
- [cross-rs/cross](https://github.com/cross-rs/cross)

## Troubleshooting Guide

### Workflow Fails on Format Check

```bash
# Fix locally
cargo fmt

# Check what would change
cargo fmt -- --check
```

### Workflow Fails on Clippy

```bash
# Run clippy locally (matching CI configuration — advisory, non-blocking)
cargo clippy --all-targets --all-features -- -W warnings

# Auto-fix issues
cargo clippy --all-targets --all-features --fix
```

### Workflow Fails on Tests

```bash
# Run tests locally
cargo test --verbose --all-features

# Run specific test
cargo test <test_name>
```

## Version History

- **2026-02-05**: Workflow fixes and improvements
  - Rewrote release pipeline with `softprops/action-gh-release@v2`
  - Added SHA256 checksums and changelog extraction
  - Fixed `macos-latest` runner compatibility (now arm64)
  - Added `cross` for Linux aarch64 builds
  - Gated Docker build to main pushes only
  - Fixed `dtolnay/rust-toolchain` action reference in validate.yml
- **2025-11-03**: Initial workflow creation
  - CI/CD pipeline with build, test, coverage
  - Release pipeline with multi-platform builds
  - Local testing configuration with `act`
