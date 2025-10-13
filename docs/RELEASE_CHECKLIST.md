# Release Checklist

Use this checklist to ensure a smooth release process for SolidityDefend.

## Pre-Release (1-2 Days Before)

### Code Quality & Testing
- [ ] All PRs merged and reviewed
- [ ] Run full test suite: `make test-all`
  - [ ] Unit tests passing
  - [ ] Integration tests passing
  - [ ] Detector validation tests passing
- [ ] Run benchmarks: `make bench-run`
- [ ] Security audit: `make audit` (no vulnerabilities)
- [ ] Check for outdated dependencies: `make outdated`
- [ ] All CI checks passing on main branch

### Documentation Updates
- [ ] Update version in `Cargo.toml` (workspace)
- [ ] Update `CHANGELOG.md` with:
  - [ ] Release date: `## [X.Y.Z] - YYYY-MM-DD`
  - [ ] Added features
  - [ ] Changed/Enhanced items
  - [ ] Fixed bugs
  - [ ] Deprecated/Removed items
  - [ ] Security fixes
- [ ] Update `README.md`:
  - [ ] Detector count (if changed)
  - [ ] Feature highlights
  - [ ] Installation instructions
  - [ ] Version badges
- [ ] Update documentation in `docs/` if needed
- [ ] Check all links in documentation

### Code Preparation
- [ ] No `TODO` comments in critical paths
- [ ] No debug logging left in production code
- [ ] All compiler warnings addressed
- [ ] Code formatted: `make fmt`
- [ ] Clippy checks pass: `make clippy`

## Local Validation (Day of Release)

### Build & Test
- [ ] Clean build: `make clean && make build`
- [ ] Full CI validation: `make ci-local`
  ```
  1/7 ✓ Code formatting
  2/7 ✓ Clippy linting
  3/7 ✓ Unit tests
  4/7 ✓ Integration tests
  5/7 ✓ Benchmarks compile
  6/7 ✓ Release build
  7/7 ✓ Documentation
  ```
- [ ] Release readiness check: `make release-check`
  ```
  ✓ Working directory clean
  ✓ On main branch
  ✓ CHANGELOG has entry
  ✓ Tag doesn't exist
  ✓ CI validation passed
  ✓ Binary builds
  ✓ Documentation present
  ✓ Security audit clean
  ```

### Binary Testing
- [ ] Build release binary: `cargo build --release --bin soliditydefend`
- [ ] Test binary functionality:
  ```bash
  ./target/release/soliditydefend --version
  # Output: soliditydefend X.Y.Z

  ./target/release/soliditydefend --help
  # Output: Help text displays correctly

  ./target/release/soliditydefend --list-detectors
  # Output: Shows all detectors with descriptions
  ```
- [ ] Run on test contracts:
  ```bash
  ./target/release/soliditydefend tests/contracts/simple.sol
  ./target/release/soliditydefend tests/contracts/2025_vulnerabilities/
  ```

### Git Status
- [ ] Working directory clean: `git status`
- [ ] On main branch: `git branch --show-current`
- [ ] Up to date with remote: `git pull origin main`

## Create Release

### Version Bump
- [ ] Determine version number (see semantic versioning guide)
- [ ] Update `Cargo.toml`: `version = "X.Y.Z"`
- [ ] Commit version bump:
  ```bash
  git add Cargo.toml CHANGELOG.md README.md
  git commit -m "chore: prepare release vX.Y.Z"
  git push origin main
  ```

### Create & Push Tag
- [ ] Create annotated tag:
  ```bash
  git tag -a vX.Y.Z -m "Release vX.Y.Z

  ## Highlights
  - Key feature 1
  - Key feature 2
  - Important fix

  See CHANGELOG.md for full details."
  ```
- [ ] Verify tag: `git show vX.Y.Z`
- [ ] Push tag: `git push origin vX.Y.Z`

### Monitor GitHub Actions
- [ ] Release workflow triggered: `gh run list --workflow=release.yml`
- [ ] All jobs succeeded:
  - [ ] create-release
  - [ ] build-release (all platforms)
  - [ ] publish-crates-io (stable releases only)
  - [ ] publish-docker (if configured)
  - [ ] update-homebrew (if configured)

## Post-Release Verification

### GitHub Release
- [ ] Release created on GitHub
- [ ] Release notes extracted from CHANGELOG
- [ ] Assets uploaded:
  - [ ] `soliditydefend-linux-x86_64.tar.gz`
  - [ ] `soliditydefend-linux-aarch64.tar.gz`
  - [ ] `soliditydefend-macos-x86_64.tar.gz`
  - [ ] `soliditydefend-macos-aarch64.tar.gz`
  - [ ] `soliditydefend-windows-x86_64.zip`

### Binary Verification
- [ ] Download and test binaries:
  ```bash
  gh release download vX.Y.Z --dir /tmp/release-test

  # macOS ARM example
  tar -xzf /tmp/release-test/soliditydefend-macos-aarch64.tar.gz -C /tmp
  /tmp/soliditydefend --version
  # Output: soliditydefend X.Y.Z
  ```
- [ ] Test on different platforms (if possible)

### Package Registry
- [ ] crates.io updated (stable releases):
  ```bash
  cargo search soliditydefend
  # Shows version X.Y.Z
  ```
- [ ] Test installation from crates.io:
  ```bash
  cargo install soliditydefend --version X.Y.Z
  soliditydefend --version
  ```

### Container Registry (if applicable)
- [ ] Docker Hub updated: `docker pull solidityops/soliditydefend:vX.Y.Z`
- [ ] Test Docker image:
  ```bash
  docker run solidityops/soliditydefend:vX.Y.Z --version
  ```

### Package Managers (if applicable)
- [ ] Homebrew formula updated
- [ ] Test Homebrew installation:
  ```bash
  brew update
  brew install soliditydefend
  soliditydefend --version
  ```

## Announcement & Communication

### GitHub
- [ ] Publish release (if draft)
- [ ] Pin release announcement
- [ ] Create discussion post in GitHub Discussions
- [ ] Close milestone: `gh issue milestone X.Y.Z --state closed`
- [ ] Create next milestone: `gh milestone create X.Y+1.0`

### Community
- [ ] Post on Twitter/X:
  ```
  🚀 SolidityDefend vX.Y.Z is here!

  ✨ Highlights:
  - [Feature 1]
  - [Feature 2]

  Download: https://github.com/SolidityOps/SolidityDefend/releases/tag/vX.Y.Z

  #Solidity #Security #Web3
  ```
- [ ] Post on Reddit:
  - [ ] r/ethdev
  - [ ] r/rust (for major releases)
- [ ] Share in Discord/Telegram communities
- [ ] Update project website (if applicable)

### Documentation
- [ ] Update online documentation
- [ ] Update examples and tutorials
- [ ] Update dependent projects
- [ ] Notify integration partners

## Post-Release Tasks

### Housekeeping
- [ ] Update project board/roadmap
- [ ] Label issues with "released in vX.Y.Z"
- [ ] Review and prioritize next release features
- [ ] Update development branch (if using gitflow)

### Monitoring
- [ ] Monitor GitHub issues for release-related problems
- [ ] Check error reports
- [ ] Monitor download statistics
- [ ] Track community feedback

### Planning Next Release
- [ ] Create next milestone
- [ ] Plan features for next release
- [ ] Update roadmap
- [ ] Schedule next release date

## Emergency Procedures

### Critical Bug Discovered
- [ ] Assess severity and impact
- [ ] Create hotfix branch
- [ ] Implement and test fix
- [ ] Create patch release (X.Y.Z+1)
- [ ] Yank problematic version from crates.io (if needed):
  ```bash
  cargo yank --vers X.Y.Z
  ```
- [ ] Mark GitHub release as pre-release
- [ ] Announce fix and encourage upgrade

### Rollback Required
- [ ] Yank from crates.io: `cargo yank --vers X.Y.Z`
- [ ] Mark as pre-release on GitHub
- [ ] Communicate issue to users
- [ ] Prepare fixed version

## Version-Specific Checklists

### Major Release (X.0.0)
- [ ] Migration guide written
- [ ] Breaking changes documented
- [ ] Deprecation warnings added in previous version
- [ ] Extended beta testing period
- [ ] Community feedback incorporated

### Minor Release (0.X.0)
- [ ] New features documented
- [ ] Examples updated
- [ ] Performance benchmarks run
- [ ] Backward compatibility verified

### Patch Release (0.0.X)
- [ ] Bug fixes tested
- [ ] Regression tests added
- [ ] Security fixes (if any) documented
- [ ] Quick turnaround release

## Sign-Off

**Release Manager:** _______________
**Date:** _______________
**Version:** v_______________

**Verification:**
- [ ] All checklist items completed
- [ ] Release successful
- [ ] No critical issues reported
- [ ] Community notified

## Notes

Use this section for release-specific notes, issues encountered, or lessons learned:

---

**Template Version:** 1.0
**Last Updated:** 2025-10-12
