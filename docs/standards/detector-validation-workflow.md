# Detector Validation Workflow Standard

**Project**: SolidityDefend
**Purpose**: Ensure detector changes don't introduce regressions or reduce accuracy

## MANDATORY: Before Modifying Any Detector

When working on detector code in `crates/detectors/`, you MUST follow this workflow.

### Step 1: Capture Baseline

```bash
./scripts/validate_detector_change.sh <detector_id>
```

This saves current findings for comparison.

### Step 2: Make Your Changes

Edit the detector code as needed.

### Step 3: Compare Results

```bash
./scripts/validate_detector_change.sh --compare <detector_id>
```

**Review the output carefully:**
- **Removed findings**: Verify EACH ONE is a false positive
- **If any removed finding is a real vulnerability**: STOP and reconsider your changes

### Step 4: Commit

```bash
git add .
git commit -m "Tighten <detector_id> detector"
```

**The pre-commit hook automatically:**
- Runs regression tests (must-detect critical vulnerabilities)
- Validates against ground truth with `--fail-on-regression`
- **Blocks the commit if validation fails**

If blocked, review the error and fix regressions before retrying.

## Pre-Commit Hook

Validation runs automatically via pre-commit when detector files are modified. This is the **primary validation checkpoint** - issues are caught before commit, not after PR.

**Location**: `.pre-commit-config.yaml` / `scripts/pre-commit-validate.sh`

To bypass (not recommended): `git commit --no-verify`

## Quick Reference Commands

| Task | Command |
|------|---------|
| Run validation | `soliditydefend --validate` |
| With thresholds | `soliditydefend --validate --min-precision 0.80 --min-recall 0.80` |
| Fail on regression | `soliditydefend --validate --fail-on-regression` |
| Baseline before changes | `./scripts/validate_detector_change.sh <detector>` |
| Compare after changes | `./scripts/validate_detector_change.sh --compare <detector>` |

## Key Files

| File | Purpose |
|------|---------|
| `tests/validation/ground_truth.json` | Labeled vulnerability dataset |
| `tests/validation/regression_tests.rs` | Must-detect critical vulnerabilities |
| `scripts/validate_detector_change.sh` | Pre-change validation script |
| `.github/workflows/validate.yml` | CI validation workflow |

## Metrics to Track

- **Precision**: Of findings reported, % that are real vulnerabilities (target: >80%)
- **Recall**: Of known vulnerabilities, % that were detected (target: >80%)
- **Regressions**: Previously detected vulnerabilities now missed (target: 0)

## When to Update Ground Truth

Add entries to `tests/validation/ground_truth.json` when:

1. You confirm a finding is a **true positive** (real vulnerability)
2. You confirm a finding is a **false positive** (not a vulnerability)
3. You add new test contracts with known vulnerabilities

## CI/CD Integration (Safety Net)

Secondary validation runs automatically on:
- PRs modifying `crates/detectors/**`
- PRs modifying `tests/validation/**`
- PRs modifying `tests/contracts/**`

This catches issues if pre-commit was bypassed. **PRs that reduce recall or cause regressions should not be merged.**

## Summary for Claude

When asked to modify a detector:

1. **Run baseline first**: `./scripts/validate_detector_change.sh <detector>`
2. **Make changes**
3. **Compare**: `./scripts/validate_detector_change.sh --compare <detector>`
4. **Review removed findings** - each must be a confirmed false positive
5. **Commit** - pre-commit hook validates automatically and blocks if regressions found
6. **If blocked**: fix regressions before retrying

The pre-commit hook ensures we don't accidentally stop detecting real vulnerabilities when reducing false positives.
