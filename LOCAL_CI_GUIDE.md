# Local CI Validation Guide

## Why Test Locally?

**GitHub Actions costs money.** Every failed CI run wastes compute minutes:

- **Failed run**: 5-10 minutes × 3 jobs = **15-30 minutes wasted**
- **Local validation**: 2-3 minutes
- **Savings**: **90% reduction** in wasted CI time

## Quick Start

### Option 1: Makefile (Recommended)

```bash
# Quick check (fastest - during development)
make quick

# Full validation (same as CI)
make ci-local

# See all available commands
make help
```

### Option 2: Manual Script

```bash
# Run validation script
./scripts/pre-push.sh

# Check release readiness
./scripts/release-check.sh
```

## What Gets Checked

All checks mirror the GitHub Actions CI pipeline:

1. **Format Check** - `cargo fmt --all -- --check`
2. **Clippy** - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
3. **Unit Tests** - `cargo test --workspace --lib`
4. **Integration Tests** - `cargo test --workspace --test '*'`
5. **Benchmark Compilation** - `cargo bench --no-run --workspace`
6. **Release Build** - `cargo build --release --workspace`
7. **Documentation** - `cargo doc --workspace --no-deps`

## Available Make Targets

### Quick Validation

```bash
make quick          # Fast check (fmt + clippy + test)
```

### Full CI Validation

```bash
make ci-local       # Complete CI validation
make pre-push       # Run validation script
```

### Code Quality

```bash
make fmt            # Auto-format code
make fmt-check      # Check formatting only
make clippy         # Run linter
```

### Testing

```bash
make test           # Unit tests only
make test-all       # All tests (unit + integration)
make test-detectors # Detector validation tests
make test-verbose   # Tests with debug output
```

### Performance

```bash
make bench          # Compile benchmarks
make bench-run      # Run benchmarks
```

### Build & Distribution

```bash
make build          # Release build
make build-all      # Build all workspace crates
make doc            # Generate docs (opens in browser)
make install        # Install binary locally
```

### Cleanup

```bash
make clean          # Clean build artifacts
make clean-cache    # Clean analysis caches
```

### Release

```bash
make release-check  # Validate release readiness
make release-dry    # Dry run release process
```

### Security

```bash
make audit          # Security audit
make outdated       # Check outdated dependencies
```

## Recommended Workflow

### 1. During Development (Fast Iteration)

```bash
# Make changes
vim crates/detectors/src/my_detector.rs

# Quick validation
make quick

# Repeat...
```

### 2. Before Committing

```bash
# Auto-format
make fmt

# Commit
git add .
git commit -m "feat: add new detector"
```

### 3. Before Pushing

```bash
# Full validation
make ci-local

# Push
git push origin feature-branch
```

### 4. Before Creating a Release

```bash
# Check release readiness
make release-check

# If all checks pass, create release
git tag -a v0.10.0 -m "Release v0.10.0"
git push origin v0.10.0
```

## Git Hooks (Optional)

Install pre-push hook for automatic validation:

```bash
# Copy hook to .git/hooks
cp scripts/pre-push.sh .git/hooks/pre-push
chmod +x .git/hooks/pre-push
```

Now validation runs automatically on `git push`. Skip with:

```bash
git push --no-verify  # Not recommended
```

## Using `act` for GitHub Actions

Test the actual GitHub Actions workflows locally:

```bash
# Install act
brew install act

# Run entire CI workflow
act -W github/workflows/ci.yml

# Run specific job
act -j test
act -j security

# Dry run
act -n
```

**Note**: Requires Docker. May not perfectly match GitHub's environment.

## Troubleshooting

### Clippy Warnings

Fix all warnings - CI has zero tolerance:

```bash
# See warnings
cargo clippy --workspace --all-targets --all-features

# Auto-fix where possible
cargo clippy --fix --workspace --all-targets --all-features
```

### Format Issues

```bash
# Auto-format all code
make fmt
```

### Test Failures

```bash
# Run with verbose output
make test-verbose

# Run specific test
cargo test --workspace test_name -- --nocapture
```

### Build Errors

```bash
# Clean and rebuild
make clean
make build
```

## Cost Comparison

### Before (No Local Validation)

- Push code → CI fails → Fix → Push → CI fails → Fix → Push → Success
- **Cost**: 3 failed runs × 20 minutes = **60 minutes**
- **Time wasted**: ~20 minutes waiting for CI

### After (With Local Validation)

- Run `make quick` → Fix locally → Push → Success
- **Cost**: 1 successful run = **10 minutes**
- **Savings**: **50 minutes** (83% reduction)

## Files

- `Makefile` - Convenient make targets
- `scripts/pre-push.sh` - Validation script
- `scripts/release-check.sh` - Release readiness check
- `LOCAL_CI_GUIDE.md` - This guide

## Summary

✅ **Always run `make quick` or `make ci-local` before pushing**

This ensures:
- No wasted CI time
- Fast feedback
- No GitHub Actions costs for preventable failures
- Same checks as CI = consistent results

## Integration with IDE

### VS Code

Add to `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Quick Check",
      "type": "shell",
      "command": "make quick",
      "group": {
        "kind": "test",
        "isDefault": true
      }
    },
    {
      "label": "CI Local",
      "type": "shell",
      "command": "make ci-local"
    }
  ]
}
```

### Vim/Neovim

Add to your config:

```vim
" Quick check
nnoremap <leader>mq :!make quick<CR>

" Full CI
nnoremap <leader>mc :!make ci-local<CR>
```
