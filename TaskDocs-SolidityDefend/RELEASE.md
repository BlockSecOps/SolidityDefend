# Release Process

Step-by-step guide for releasing new versions of SolidityDefend.

## Pre-Release Checklist

- [ ] All unit tests pass (`cargo test --workspace --lib`)
- [ ] Real-world contract tests pass
- [ ] Version bumped in `Cargo.toml`
- [ ] CHANGELOG updated
- [ ] Documentation updated

## Release Steps

### 1. Version Bump

Update version in workspace Cargo.toml:

```toml
[workspace.package]
version = "X.Y.Z"
```

### 2. Build Release Binary

```bash
cargo build --release
```

### 3. Create Release Archive

```bash
# macOS x86_64
tar -czvf soliditydefend-vX.Y.Z-darwin-x86_64.tar.gz \
  -C target/release soliditydefend

# Linux x86_64
tar -czvf soliditydefend-vX.Y.Z-linux-x86_64.tar.gz \
  -C target/release soliditydefend
```

### 4. Calculate SHA256

```bash
shasum -a 256 soliditydefend-vX.Y.Z-darwin-x86_64.tar.gz
```

### 5. Create GitHub Release

```bash
gh release create vX.Y.Z \
  --title "vX.Y.Z: Release Title" \
  --notes "Release notes here"

gh release upload vX.Y.Z \
  soliditydefend-vX.Y.Z-darwin-x86_64.tar.gz
```

### 6. Update Homebrew Formula

Edit `Formula/soliditydefend.rb`:
- Update `version`
- Update `url`
- Update `sha256`

### 7. Verify Installation

```bash
brew update
brew upgrade soliditydefend
soliditydefend --version
```

## Post-Release Verification

### Functional Tests

```bash
# List detectors
soliditydefend --list-detectors | wc -l
# Expected: 333

# Test against real contracts
soliditydefend /tmp/test-contracts/

# Framework detection
soliditydefend /tmp/foundry-test/  # Should detect Foundry
soliditydefend /tmp/hardhat-test/  # Should detect Hardhat
```

### Test Matrix

| Test | Command | Expected |
|------|---------|----------|
| Version | `--version` | vX.Y.Z |
| Detectors | `--list-detectors` | 333 |
| Proxy | OpenZeppelin Proxy | 28 findings |
| Foundry | Permit2 | 54 findings |
| Hardhat | Aave V3 | 146 findings |

## Rollback Procedure

If issues are discovered after release:

1. Delete the release: `gh release delete vX.Y.Z`
2. Delete the tag: `git push --delete origin vX.Y.Z`
3. Fix issues
4. Create new release with incremented patch version

## Version History

| Version | Date | Notes |
|---------|------|-------|
| 1.10.13 | 2026-01-30 | Project-aware scanning, FP reduction |
| 1.10.12 | 2026-01-29 | Bug fixes |
| 1.10.11 | 2026-01-28 | New detectors |
