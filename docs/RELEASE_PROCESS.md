# Release Process

This document describes the complete release process for SolidityDefend.

## Release Schedule

SolidityDefend follows a **time-based release schedule** with **semantic versioning**:

### Release Cadence

- **Major releases (X.0.0)**: Every 6-12 months (breaking changes, major features)
- **Minor releases (0.X.0)**: Every 4-6 weeks (new features, detectors)
- **Patch releases (0.0.X)**: As needed (bug fixes, security patches)

### Version Milestones

- **v0.9.0** (Current): Pre-release with 78 detectors, feature complete
- **v1.0.0** (Target: Q1 2026): Stable release with 100+ detectors, full validation
- **v1.1.0+**: Regular feature releases with new detector phases

## Prerequisites

### Required Tools

1. **Rust Toolchain**
   ```bash
   rustup update stable
   ```

2. **GitHub CLI** (optional but recommended)
   ```bash
   brew install gh
   gh auth login
   ```

3. **Local Dependencies**
   ```bash
   cargo install cargo-audit
   cargo install act  # For local GitHub Actions testing
   ```

### Required Secrets

Configure these secrets in GitHub repository settings:

1. **CARGO_REGISTRY_TOKEN** - For publishing to crates.io
   - Create at: https://crates.io/settings/tokens
   - Add to: Repository → Settings → Secrets and variables → Actions

2. **DOCKER_USERNAME** & **DOCKER_PASSWORD** - For Docker Hub (optional)
   - Create at: https://hub.docker.com/settings/security

3. **HOMEBREW_TOKEN** - For Homebrew tap updates (optional)
   - Create GitHub personal access token with `repo` scope

## Release Checklist

### Phase 1: Preparation (1-2 days before)

- [ ] Review all merged PRs since last release
- [ ] Update version in `Cargo.toml` (workspace version)
- [ ] Update `CHANGELOG.md` with release notes
- [ ] Update `README.md` if needed (detector counts, features)
- [ ] Run full test suite: `make test-all`
- [ ] Run security audit: `make audit`
- [ ] Test all detector patterns: `make test-detectors`
- [ ] Update documentation: `make doc`

### Phase 2: Local Validation

```bash
# 1. Run full CI validation locally
make ci-local

# 2. Check release readiness
make release-check

# 3. Build and test release binary
cargo build --release --bin soliditydefend
./target/release/soliditydefend --version
./target/release/soliditydefend --help
./target/release/soliditydefend --list-detectors

# 4. Test on sample contracts
./target/release/soliditydefend tests/contracts/simple.sol
./target/release/soliditydefend tests/contracts/2025_vulnerabilities/
```

### Phase 3: Version Bump & Commit

```bash
# Current version from Cargo.toml
CURRENT_VERSION=$(grep '^version = ' Cargo.toml | head -1 | cut -d'"' -f2)
echo "Current version: $CURRENT_VERSION"

# Example: Bumping from 0.9.0 to 0.10.0
NEW_VERSION="0.10.0"

# Update workspace version
sed -i '' "s/version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml

# Commit changes
git add Cargo.toml CHANGELOG.md README.md
git commit -m "chore: prepare release v${NEW_VERSION}"
git push origin main
```

### Phase 4: Create Release Tag

```bash
# Create annotated tag
git tag -a v${NEW_VERSION} -m "Release v${NEW_VERSION}

## Highlights
- [Add key features here]
- [Add important fixes here]

See CHANGELOG.md for full details."

# Verify tag
git show v${NEW_VERSION}

# Push tag to trigger release workflow
git push origin v${NEW_VERSION}
```

### Phase 5: Automated Release Workflow

The GitHub Actions workflow automatically:

1. **Creates GitHub Release**
   - Extracts release notes from CHANGELOG.md
   - Creates draft or final release

2. **Builds Multi-Platform Binaries**
   - Linux: x86_64, ARM64
   - macOS: Intel (x86_64), Apple Silicon (ARM64)
   - Windows: x86_64

3. **Uploads Release Assets**
   - `soliditydefend-linux-x86_64.tar.gz`
   - `soliditydefend-linux-aarch64.tar.gz`
   - `soliditydefend-macos-x86_64.tar.gz`
   - `soliditydefend-macos-aarch64.tar.gz`
   - `soliditydefend-windows-x86_64.zip`

4. **Publishes to crates.io** (for stable releases only)
   - Skips pre-release versions (with `-` in version)

5. **Updates Docker Hub** (optional, if configured)
   - Multi-platform images: linux/amd64, linux/arm64

6. **Updates Homebrew Formula** (optional, if configured)

### Phase 6: Post-Release Verification

```bash
# 1. Verify GitHub release created
gh release view v${NEW_VERSION}

# 2. Verify binaries uploaded
gh release download v${NEW_VERSION} --dir /tmp/release-test

# 3. Test downloaded binaries (macOS example)
tar -xzf /tmp/release-test/soliditydefend-macos-aarch64.tar.gz -C /tmp
/tmp/soliditydefend --version

# 4. Verify crates.io publication (for stable releases)
cargo search soliditydefend

# 5. Test installation from crates.io
cargo install soliditydefend --version ${NEW_VERSION}
soliditydefend --version
```

### Phase 7: Announcement & Documentation

- [ ] Publish GitHub release (if draft)
- [ ] Post announcement in GitHub Discussions
- [ ] Update project website (if applicable)
- [ ] Share on social media:
  - Twitter/X (@SolidityOps)
  - Reddit (r/ethdev, r/rust)
  - Discord/Telegram communities
- [ ] Update dependent projects/examples
- [ ] Close milestone in GitHub
- [ ] Create next milestone

## Version Numbering

We follow [Semantic Versioning 2.0.0](https://semver.org/):

### MAJOR version (X.0.0)
- Breaking API changes
- Incompatible CLI changes
- Major architectural changes

**Examples:**
- v0.9.0 → v1.0.0: Stable API, production-ready
- v1.0.0 → v2.0.0: Complete API redesign

### MINOR version (0.X.0)
- New features (backward compatible)
- New detector phases
- Performance improvements
- Non-breaking enhancements

**Examples:**
- v0.9.0 → v0.10.0: New detector phase, additional features
- v1.0.0 → v1.1.0: Enhanced analysis capabilities

### PATCH version (0.0.X)
- Bug fixes
- Security patches
- Documentation updates
- Performance tweaks

**Examples:**
- v0.9.0 → v0.9.1: Critical bug fix
- v1.0.0 → v1.0.1: Security vulnerability patch

### Pre-release versions
- Alpha: `v0.10.0-alpha.1` (internal testing)
- Beta: `v0.10.0-beta.1` (public testing)
- RC: `v0.10.0-rc.1` (release candidate)

## Troubleshooting

### Release Workflow Failed

1. **Check GitHub Actions logs**
   ```bash
   gh run list --workflow=release.yml
   gh run view [RUN_ID]
   ```

2. **Common issues:**
   - Missing secrets (CARGO_REGISTRY_TOKEN)
   - Version already exists on crates.io
   - Build failures on specific platforms

3. **Retry failed jobs:**
   ```bash
   gh run rerun [RUN_ID]
   ```

### Binary Build Failed

Test locally for each target:

```bash
# macOS ARM (current machine)
cargo build --release --target aarch64-apple-darwin

# macOS Intel
cargo build --release --target x86_64-apple-darwin

# Linux (requires cross)
cargo install cross
cross build --release --target x86_64-unknown-linux-gnu
```

### crates.io Publish Failed

```bash
# Manual publish
cd crates/soliditydefend
cargo publish --dry-run  # Verify first
cargo publish --token $CARGO_REGISTRY_TOKEN
```

### Homebrew Update Failed

Manually update formula:

```bash
# Calculate sha256
wget https://github.com/SolidityOps/SolidityDefend/archive/refs/tags/v${NEW_VERSION}.tar.gz
sha256sum v${NEW_VERSION}.tar.gz

# Update formula with new version and sha256
# Push to homebrew-tap repository
```

## Rollback Procedures

### If Release Has Critical Issues

1. **Yank from crates.io** (doesn't delete, prevents new uses)
   ```bash
   cargo yank --vers ${VERSION}
   ```

2. **Mark GitHub Release as Pre-release**
   ```bash
   gh release edit v${VERSION} --prerelease
   ```

3. **Create Hotfix Release**
   ```bash
   # Fix the issue
   git checkout -b hotfix/v${VERSION}-fix
   # ... make fixes ...
   git commit -m "fix: critical issue in ${VERSION}"

   # Create patch version
   PATCH_VERSION="${VERSION%.*}.$((${VERSION##*.}+1))"
   git tag -a v${PATCH_VERSION} -m "Hotfix release v${PATCH_VERSION}"
   git push origin v${PATCH_VERSION}
   ```

4. **Announce the Fix**
   - Update GitHub release notes
   - Post announcement
   - Encourage immediate upgrade

## Emergency Security Release

For critical security vulnerabilities:

1. **DO NOT** discuss vulnerability publicly before release
2. Prepare fix in **private branch**
3. Follow expedited release process:
   ```bash
   # Create private security branch
   git checkout -b security/critical-fix

   # ... implement fix ...

   # Test thoroughly
   make ci-local

   # Create patch release immediately
   git tag -a v${PATCH_VERSION} -m "Security patch v${PATCH_VERSION}"
   git push origin v${PATCH_VERSION}
   ```
4. Mark as **security release** in GitHub
5. Publish CVE if applicable
6. Send security advisory to users
7. Encourage **immediate upgrade**

## Release Artifacts

Each release produces:

### 1. Source Archives
- GitHub: `.tar.gz` source archive
- crates.io: Published crate

### 2. Binary Archives
- Linux x86_64: `soliditydefend-linux-x86_64.tar.gz`
- Linux ARM64: `soliditydefend-linux-aarch64.tar.gz`
- macOS Intel: `soliditydefend-macos-x86_64.tar.gz`
- macOS Apple Silicon: `soliditydefend-macos-aarch64.tar.gz`
- Windows: `soliditydefend-windows-x86_64.zip`

### 3. Container Images (optional)
- Docker Hub: `solidityops/soliditydefend:latest`
- Tagged versions: `solidityops/soliditydefend:v${VERSION}`

### 4. Package Managers
- Cargo: `cargo install soliditydefend`
- Homebrew: `brew install soliditydefend` (if tap configured)

## Contact & Support

**For release questions:**
- Open GitHub issue: https://github.com/SolidityOps/SolidityDefend/issues
- Contact maintainers: team@solidityops.com
- Security issues: security@solidityops.com

## Additional Resources

- [RELEASE_CHECKLIST.md](./RELEASE_CHECKLIST.md) - Detailed checklist
- [LOCAL_CI_GUIDE.md](../LOCAL_CI_GUIDE.md) - Local validation guide
- [CHANGELOG.md](../CHANGELOG.md) - Version history
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Development guide
