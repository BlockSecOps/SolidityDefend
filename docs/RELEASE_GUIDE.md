# Release Guide for SolidityDefend

This guide explains how to create a new release of SolidityDefend using local build scripts.

## Overview

SolidityDefend uses a **local release process** where you build binaries on your machine and then upload them to GitHub. This gives you full control over the release process.

## Prerequisites

### Required Tools

- **Rust** 1.75.0+ with rustup
- **Git** for version control
- **GitHub CLI** (`gh`) for creating releases
  ```bash
  # macOS
  brew install gh

  # Linux
  # See https://github.com/cli/cli/blob/trunk/docs/install_linux.md

  # Authenticate
  gh auth login
  ```

### Optional Tools (for cross-compilation)

- **cross** for Linux ARM64 builds
  ```bash
  cargo install cross --git https://github.com/cross-rs/cross
  ```

## Release Process

### 1. Prepare the Release

#### Update Version

Update version in `Cargo.toml`:
```toml
[workspace.package]
version = "1.0.1"  # Update to new version
```

#### Update CHANGELOG.md

Add a new section for the release:
```markdown
## [1.0.1] - 2025-10-XX

### Added
- New feature description

### Fixed
- Bug fix description

### Changed
- Change description
```

#### Commit Changes

```bash
git add Cargo.toml CHANGELOG.md
git commit -m "chore: bump version to 1.0.1"
git push origin main
```

### 2. Build Release Binaries

Run the local build script:

```bash
./scripts/build-release.sh 1.0.1
```

This will:
- Build optimized release binary for your current platform
- Attempt to cross-compile for other platforms (may not work for all)
- Place binaries in `target/release-builds/`

**Output:**
```
target/release-builds/
├── soliditydefend-x86_64-apple-darwin
├── soliditydefend-aarch64-apple-darwin
└── soliditydefend-x86_64-unknown-linux-gnu (if on Linux)
```

**Note:** Cross-compilation may not work for all platforms from your host. See [Cross-Platform Builds](#cross-platform-builds) for alternatives.

### 3. Create GitHub Release

Run the release creation script:

```bash
./scripts/create-release.sh 1.0.1
```

This will:
1. Create `.tar.gz` archives for each binary
2. Generate SHA256 checksums
3. Extract changelog for this version
4. Create git tag `v1.0.1`
5. Push tag to GitHub
6. Create GitHub release
7. Upload all binaries and checksums
8. Update Homebrew formula with new SHA256s

**Interactive prompts:**
- Confirm tag creation/recreation
- Confirm tag push to GitHub
- Confirm GitHub release creation

**Output:**
```
releases/v1.0.1/
├── soliditydefend-v1.0.1-x86_64-apple-darwin.tar.gz
├── soliditydefend-v1.0.1-aarch64-apple-darwin.tar.gz
├── soliditydefend-v1.0.1-x86_64-unknown-linux-gnu.tar.gz
├── SHA256SUMS.txt
└── release_notes.md
```

### 4. Verify Release

#### Test Installation Script

```bash
# Test quick install
curl -sSfL https://raw.githubusercontent.com/SolidityOps/SolidityDefend/main/install.sh | bash

# Or with specific version
curl -sSfL https://raw.githubusercontent.com/SolidityOps/SolidityDefend/main/install.sh | VERSION=v1.0.1 bash
```

#### Test Binary Downloads

Download and test each platform binary:
```bash
# macOS Intel
curl -L https://github.com/SolidityOps/SolidityDefend/releases/download/v1.0.1/soliditydefend-v1.0.1-x86_64-apple-darwin.tar.gz | tar xz
./soliditydefend --version

# macOS Apple Silicon
curl -L https://github.com/SolidityOps/SolidityDefend/releases/download/v1.0.1/soliditydefend-v1.0.1-aarch64-apple-darwin.tar.gz | tar xz
./soliditydefend --version
```

#### Verify Checksums

```bash
# Download checksums
curl -L https://github.com/SolidityOps/SolidityDefend/releases/download/v1.0.1/SHA256SUMS.txt

# Verify
shasum -a 256 -c SHA256SUMS.txt
```

### 5. Update Homebrew Tap (Optional)

If you have a Homebrew tap repository (`homebrew-tap`):

```bash
# The formula is already updated by create-release.sh
# Just commit and push
git add Formula/soliditydefend.rb
git commit -m "chore: update formula to v1.0.1"
git push
```

### 6. Announce the Release

Create announcement in GitHub Discussions:
```markdown
## 🎉 SolidityDefend v1.0.1 Released!

### Installation

**Quick install:**
\`\`\`bash
curl -sSfL https://raw.githubusercontent.com/SolidityOps/SolidityDefend/main/install.sh | bash
\`\`\`

**Homebrew:**
\`\`\`bash
brew upgrade soliditydefend
\`\`\`

**Direct download:** See [releases page](...)

### What's New

[Summary of changes from CHANGELOG]

### Full Changelog

See [CHANGELOG.md](...)
```

## Cross-Platform Builds

### Building on macOS

On macOS, you can build for:
- ✅ x86_64-apple-darwin (Intel Mac)
- ✅ aarch64-apple-darwin (Apple Silicon)
- ❌ Linux (requires Docker or Linux machine)
- ❌ Windows (requires Windows machine or Docker)

### Building on Linux

On Linux, you can build for:
- ✅ x86_64-unknown-linux-gnu (Intel/AMD)
- ✅ aarch64-unknown-linux-gnu (ARM64, with `cross`)
- ❌ macOS (requires macOS machine)
- ❌ Windows (requires Windows machine or Docker)

### Solution: Use Docker for Missing Platforms

Create a Docker-based build:

```bash
# Build all platforms using Docker
docker run --rm -v $(pwd):/project rust:latest bash -c "
  cd /project &&
  cargo build --release --target x86_64-unknown-linux-gnu
"
```

Or use GitHub Actions if you prefer (though you mentioned running locally).

### Alternative: Build on Multiple Machines

1. **Build on macOS**: Get macOS binaries
2. **Build on Linux**: Get Linux binaries
3. **Build on Windows**: Get Windows binaries
4. **Collect all**: Place all binaries in `target/release-builds/`
5. **Run**: `./scripts/create-release.sh`

## Troubleshooting

### "gh: command not found"

Install GitHub CLI:
```bash
# macOS
brew install gh

# Linux (Debian/Ubuntu)
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list
sudo apt update
sudo apt install gh

# Authenticate
gh auth login
```

### "No binaries found"

Run build script first:
```bash
./scripts/build-release.sh 1.0.1
```

### "Cross-compilation failed"

This is normal. Cross-compilation doesn't work for all platforms from a single host. Options:
1. Only release binaries for your current platform
2. Build on multiple machines
3. Use Docker for missing platforms

### "Tag already exists"

The script will prompt to delete and recreate. Or manually:
```bash
git tag -d v1.0.1
git push origin :v1.0.1
```

### "Release already exists"

The script will prompt to delete and recreate. Or manually:
```bash
gh release delete v1.0.1 -y
```

## Quick Reference

### Complete Release Workflow

```bash
# 1. Update version and changelog
vim Cargo.toml CHANGELOG.md
git add Cargo.toml CHANGELOG.md
git commit -m "chore: bump version to 1.0.1"
git push

# 2. Build binaries
./scripts/build-release.sh 1.0.1

# 3. Create release
./scripts/create-release.sh 1.0.1

# 4. Verify
curl -sSfL https://raw.githubusercontent.com/SolidityOps/SolidityDefend/main/install.sh | VERSION=v1.0.1 bash
soliditydefend --version

# 5. Announce (GitHub Discussions)
```

### Script Arguments

Both scripts accept optional version argument:

```bash
# Use version from Cargo.toml (default)
./scripts/build-release.sh
./scripts/create-release.sh

# Specify version explicitly
./scripts/build-release.sh 1.0.1
./scripts/create-release.sh 1.0.1
```

## Cleanup

After release, clean up build artifacts:

```bash
# Remove release builds
rm -rf target/release-builds

# Remove release archives
rm -rf releases/v1.0.1

# Keep git tags and GitHub releases
```

## Best Practices

1. **Test locally first**: Build and test binaries before creating release
2. **Update CHANGELOG**: Always document changes
3. **Semantic versioning**: Follow semver (MAJOR.MINOR.PATCH)
4. **Verify checksums**: Check SHA256 after uploading
5. **Test installation**: Verify install script works
6. **Announce**: Post in Discussions for visibility

## Support

For questions or issues:
- 📖 [Documentation](../README.md)
- 🐛 [Issues](https://github.com/SolidityOps/SolidityDefend/issues)
- 💬 [Discussions](https://github.com/SolidityOps/SolidityDefend/discussions)
