# SolidityDefend Scripts

This directory contains automation scripts for local CI validation and release management.

## Scripts Overview

### `pre-push.sh`
**Purpose:** Pre-push validation to prevent wasted GitHub Actions minutes

**Usage:**
```bash
./scripts/pre-push.sh
```

**What it does:**
1. ✓ Code formatting check
2. ✓ Clippy linting (strict mode)
3. ✓ Unit tests
4. ✓ Integration tests
5. ✓ Benchmark compilation
6. ✓ Release build
7. ✓ Documentation generation

**Exit codes:**
- `0` - All checks passed
- `1` - One or more checks failed

**When to use:**
- Before every `git push`
- After major code changes
- Before creating pull requests

**Alternative:** Use `make ci-local` for the same validation

---

### `release-check.sh`
**Purpose:** Validate release readiness before creating a release tag

**Usage:**
```bash
./scripts/release-check.sh
```

**What it does:**
1. ✓ Git status clean (no uncommitted changes)
2. ✓ On main branch
3. ✓ CHANGELOG.md has entry for current version
4. ✓ Version tag doesn't exist yet
5. ✓ Full CI validation passes
6. ✓ Binary builds successfully
7. ✓ Documentation files present
8. ✓ Security audit clean

**Exit codes:**
- `0` - Ready for release
- `1` - Issues found, not ready

**When to use:**
- Before creating release tags
- During release preparation
- To validate release readiness

**Alternative:** Use `make release-check`

**Output example:**
```
======================================
SolidityDefend Release Readiness Check
======================================

Current Version: 0.9.0

1. Checking git status...
✓ Working directory is clean

2. Checking branch...
✓ On main branch

3. Checking CHANGELOG.md...
✓ CHANGELOG.md has entry for 0.9.0

4. Checking for existing tag...
✓ Tag v0.9.0 does not exist

5. Running CI validation...
✓ All CI checks passed

6. Checking binary build...
✓ Binary builds successfully (12M)

7. Checking documentation...
✓ Documentation files present

8. Running security audit...
✓ No security vulnerabilities found

======================================
✓ Release readiness check passed!

Next steps:
1. Review changes: git log --oneline -10
2. Create tag: git tag -a v0.9.0 -m "Release v0.9.0"
3. Push tag: git push origin v0.9.0
4. GitHub Actions will create the release automatically
======================================
```

---

## Installation & Setup

### Make Scripts Executable

```bash
chmod +x scripts/*.sh
```

### Install as Git Hooks (Optional)

#### Pre-push Hook

Automatically run validation before every push:

```bash
# Copy to git hooks
cp scripts/pre-push.sh .git/hooks/pre-push
chmod +x .git/hooks/pre-push
```

Now validation runs automatically on `git push`.

**Bypass hook (not recommended):**
```bash
git push --no-verify
```

#### Pre-commit Hook

For stricter validation:

```bash
# Create pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Pre-commit validation
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
EOF

chmod +x .git/hooks/pre-commit
```

---

## Cost Savings

### Without Local Validation
```
Developer workflow:
1. Write code
2. git push
3. Wait 5 min → CI fails (formatting)
4. Fix locally
5. git push
6. Wait 5 min → CI fails (clippy warning)
7. Fix locally
8. git push
9. Wait 5 min → CI succeeds

Total time: 15 minutes CI + 15 minutes waiting = 30 minutes
GitHub Actions cost: 15 minutes
```

### With Local Validation
```
Developer workflow:
1. Write code
2. make quick (30 seconds)
3. Fix issues immediately
4. git push
5. Wait 5 min → CI succeeds

Total time: 5 minutes CI + 5 minutes waiting = 10 minutes
GitHub Actions cost: 5 minutes
Savings: 67% time, 67% cost
```

### Annual Savings (Example)

**Team:** 5 developers
**Failed CI runs per week:** 10 (without local validation)
**CI run cost:** ~5 minutes each

**Without validation:**
- Wasted CI minutes/week: 50 minutes
- Wasted CI minutes/year: 2,600 minutes (~43 hours)

**With validation:**
- Wasted CI minutes/week: ~5 minutes (rare failures)
- Wasted CI minutes/year: 260 minutes (~4 hours)

**Annual savings: 2,340 minutes (~39 hours) of GitHub Actions time**

---

## Troubleshooting

### Script Fails: "Permission denied"

```bash
chmod +x scripts/*.sh
```

### Script Fails: "cargo: command not found"

Install Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Script Fails: "cargo-audit not installed"

```bash
cargo install cargo-audit
```

### Clippy Failures

Auto-fix where possible:
```bash
cargo clippy --fix --workspace --all-targets --all-features
```

### Format Failures

Auto-format:
```bash
cargo fmt --all
```

### Test Failures

Run with verbose output:
```bash
RUST_LOG=debug cargo test --workspace -- --nocapture
```

---

## Integration with Development Tools

### VS Code

Add to `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Pre-push Validation",
      "type": "shell",
      "command": "./scripts/pre-push.sh",
      "group": {
        "kind": "test",
        "isDefault": true
      },
      "presentation": {
        "reveal": "always",
        "panel": "new"
      }
    },
    {
      "label": "Release Check",
      "type": "shell",
      "command": "./scripts/release-check.sh",
      "presentation": {
        "reveal": "always",
        "panel": "new"
      }
    }
  ]
}
```

Run with: `Cmd+Shift+P` → "Tasks: Run Task"

### Vim/Neovim

Add to your config:

```vim
" Quick validation
nnoremap <leader>cv :!./scripts/pre-push.sh<CR>

" Release check
nnoremap <leader>cr :!./scripts/release-check.sh<CR>
```

### JetBrains IDEs (IntelliJ, CLion)

1. Go to: Run → Edit Configurations
2. Add new "Shell Script" configuration
3. Script path: `scripts/pre-push.sh`
4. Working directory: Project root
5. Save as "Pre-push Validation"

---

## CI/CD Integration

### GitHub Actions

The scripts mirror the GitHub Actions workflow:

**Local:** `./scripts/pre-push.sh`
**GitHub:** `.github/workflows/ci.yml`

Same checks, same results, faster feedback locally.

### Pre-commit Framework

Use with [pre-commit](https://pre-commit.com/):

`.pre-commit-config.yaml`:
```yaml
repos:
  - repo: local
    hooks:
      - id: cargo-fmt
        name: Cargo Format
        entry: cargo fmt --all -- --check
        language: system
        pass_filenames: false

      - id: cargo-clippy
        name: Cargo Clippy
        entry: cargo clippy --workspace --all-targets --all-features -- -D warnings
        language: system
        pass_filenames: false

      - id: cargo-test
        name: Cargo Test
        entry: cargo test --workspace --lib
        language: system
        pass_filenames: false
```

Install:
```bash
pip install pre-commit
pre-commit install
```

---

## Best Practices

### Daily Development
```bash
# Fast iteration
make quick  # or ./scripts/pre-push.sh with --quick flag
```

### Before Commits
```bash
# Format code
make fmt
```

### Before Pushing
```bash
# Full validation
make ci-local  # or ./scripts/pre-push.sh
```

### Before Releases
```bash
# Comprehensive check
make release-check  # or ./scripts/release-check.sh
```

---

## Script Maintenance

### Adding New Checks

Edit `scripts/pre-push.sh`:

```bash
# Add new check
run_check "My new check" "my-command --args"
```

### Customizing Checks

Set environment variables:

```bash
# Skip certain checks
SKIP_BENCH=1 ./scripts/pre-push.sh

# Change timeout
CARGO_TEST_TIMEOUT=300 ./scripts/pre-push.sh
```

### Performance Tuning

For faster validation:

```bash
# Parallel builds
CARGO_BUILD_JOBS=8 ./scripts/pre-push.sh

# Incremental compilation
export CARGO_INCREMENTAL=1
```

---

## Related Documentation

- [LOCAL_CI_GUIDE.md](../LOCAL_CI_GUIDE.md) - Comprehensive local CI guide
- [RELEASE_PROCESS.md](../docs/RELEASE_PROCESS.md) - Release process
- [RELEASE_CHECKLIST.md](../docs/RELEASE_CHECKLIST.md) - Release checklist
- [Makefile](../Makefile) - Make targets reference

---

**Last Updated:** 2025-10-12
