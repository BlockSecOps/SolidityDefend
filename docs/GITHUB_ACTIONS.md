# GitHub Actions CI/CD

This document describes the GitHub Actions workflows configured for SolidityDefend and how to test them locally.

## Workflows

### CI/CD Pipeline (`.github/workflows/ci.yml`)

**Triggers:** Push to `main` or `develop`, Pull Requests to `main`

**Jobs:**

1. **Build and Test**
   - Install Rust toolchain (stable)
   - Run code formatting checks (`cargo fmt`)
   - Run clippy linter (`cargo clippy`)
   - Build in debug and release modes
   - Run all tests
   - Verify detector count (209 expected)
   - Upload build artifacts

2. **Docker Build**
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

**Jobs:**

1. **Create Release**
   - Extract version from tag
   - Create GitHub release

2. **Build Release** (Matrix Strategy)
   - Build for multiple platforms:
     - Linux (x86_64, aarch64)
     - macOS (x86_64, aarch64)
     - Windows (x86_64)
   - Package binaries
   - Upload to GitHub release

3. **Publish Docker**
   - Build multi-platform Docker images
   - Push to Docker Hub with version tags

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

**Security Report:**
- File: `security-report.json`
- Retention: 30 days

### Secrets Required (for full CI/CD)

For release workflows, configure these secrets in GitHub:

- `DOCKER_USERNAME` - Docker Hub username
- `DOCKER_PASSWORD` - Docker Hub access token
- `GITHUB_TOKEN` - Automatically provided by GitHub Actions

### GitHub Actions Runner Compatibility

The workflows use:
- `ubuntu-latest` (Ubuntu 22.04)
- `macos-latest` (macOS 14)
- `windows-latest` (Windows Server 2022)

Local testing with `act` uses `catthehacker/ubuntu:act-latest` which closely matches GitHub's runner environment.

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

- ✅ Require status checks to pass
  - `build-and-test`
  - `docker-build`
- ✅ Require branches to be up to date
- ✅ Require linear history
- ✅ Include administrators

### Pull Request Checks

All PRs to `main` automatically run:
1. Format checking
2. Linting (clippy)
3. Tests
4. Docker build
5. Security scan

## Continuous Deployment

### Automatic Releases

Create a release by pushing a tag:

```bash
# Tag the release
git tag -a v1.4.0 -m "Release v1.4.0"
git push origin v1.4.0
```

This triggers:
1. Release creation
2. Multi-platform binary builds
3. Docker image publication
4. GitHub release with downloadable artifacts

### Manual Workflow Dispatch

Workflows can be manually triggered from GitHub Actions tab:

1. Go to Actions → Select workflow
2. Click "Run workflow"
3. Select branch
4. Run

## Performance Optimization

### Parallelization

The CI pipeline runs jobs in parallel when possible:

```
Stage 0 (Parallel):
├── build-and-test
├── docker-build
└── coverage

Stage 1 (Sequential):
└── security-scan (needs: build-and-test)
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
# Run clippy locally
cargo clippy --all-targets --all-features -- -D warnings

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

- **2025-11-03**: Initial workflow creation
  - CI/CD pipeline with build, test, coverage
  - Release pipeline with multi-platform builds
  - Local testing configuration with `act`
