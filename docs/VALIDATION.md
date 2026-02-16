# Detector Validation Framework

This document describes how to validate detector accuracy against a ground truth dataset, track precision/recall metrics, and prevent regressions when modifying detectors.

## Quick Start

```bash
# Run validation against ground truth
./target/release/soliditydefend --validate

# With thresholds (fails if not met)
./target/release/soliditydefend --validate --min-precision 0.85 --min-recall 0.80

# Fail on any regression
./target/release/soliditydefend --validate --fail-on-regression
```

## Why Validate?

When tightening detectors to reduce false positives, we need to verify:

1. **Removed findings were actually false positives** - Not real vulnerabilities
2. **True vulnerabilities are still detected** - No regressions
3. **Changes don't break detection of known issues** - Critical exploits still caught

**Without validation**: Count findings and hope the reduction is good.
**With validation**: Track precision/recall against labeled ground truth.

## Components

### 1. Ground Truth Dataset

**Location**: `tests/validation/ground_truth.json` (v1.2.0)

**Coverage**: 117 contracts (100% of test corpus)

| Metric | Count |
|--------|-------|
| Total contracts | 117 |
| Clean/secure contracts | 43 |
| Vulnerable contracts | 74 |
| Expected true positives | 103 |
| Parse error contracts | 0 |
| Vulnerability categories | 26 |
| Validated recall | 100% (103/103) |
| False positives | 65 |
| Precision | 61.3% |

Contains labeled vulnerability data:
- **Expected findings**: Known vulnerabilities that detectors should report (78 TPs, aligned to actual detector IDs)
- **Known false positives**: Findings that detectors incorrectly report
- **Clean sections**: Code that is intentionally secure (43 contracts where all findings are FPs)

```json
{
  "contracts": {
    "tests/contracts/basic_vulnerabilities/reentrancy_issues.sol": {
      "expected_findings": [
        {
          "detector_id": "classic-reentrancy",
          "line_range": [28, 34],
          "severity": "high",
          "description": "Classic reentrancy in withdrawBasedOnBalance()"
        }
      ],
      "known_false_positives": [],
      "clean_sections": []
    },
    "tests/contracts/fp_benchmarks/safe_amm_pool.sol": {
      "expected_findings": [],
      "clean_sections": [{"description": "Secure AMM - any findings are FPs"}]
    }
  }
}
```

### 2. Validation Command

```bash
soliditydefend --validate [OPTIONS]

OPTIONS:
  --ground-truth <FILE>    Path to ground truth JSON (default: tests/validation/ground_truth.json)
  --fail-on-regression     Exit with error if any expected finding is missed
  --min-precision <0.0-1.0> Minimum precision threshold
  --min-recall <0.0-1.0>    Minimum recall threshold
```

**Output**:
```
╔══════════════════════════════════════════════════════════════╗
║              DETECTOR VALIDATION RESULTS                     ║
╚══════════════════════════════════════════════════════════════╝

OVERALL METRICS
═══════════════
  True Positives:   142 / 150 (94.7%)
  False Negatives:    8 / 150 (5.3%)  <- Missed real vulnerabilities
  False Positives:   23 / 165 (13.9%)

  Precision: 86.1%
  Recall:    94.7%
  F1 Score:  0.902

PER-DETECTOR METRICS
════════════════════
  Detector                    TP    FP    FN   Prec   Recall   F1
  ─────────────────────────────────────────────────────────────────
  reentrancy                   12     2     1   85.7%   92.3%  0.889
  access-control               10     3     0  100.0%   76.9%  0.870
  oracle-manipulation           8     1     2   88.9%   80.0%  0.842
```

### 3. Pre-Change Validation Script

**Location**: `scripts/validate_detector_change.sh`

Use this workflow when modifying a detector:

```bash
# Step 1: Before making changes, capture baseline
./scripts/validate_detector_change.sh reentrancy

# Step 2: Make your detector changes
# ... edit crates/detectors/src/reentrancy.rs ...

# Step 3: Compare findings after changes
./scripts/validate_detector_change.sh --compare reentrancy

# Review removed findings - verify they are all false positives!
```

### 4. Regression Test Suite

**Location**: `tests/validation/regression_tests.rs`

Contains must-detect test cases for critical vulnerabilities:

- Classic reentrancy patterns
- Missing access control
- Oracle manipulation (Euler Finance pattern)
- Share inflation attacks (Cetus DEX pattern)
- Flash loan governance attacks (Beanstalk pattern)
- Cross-chain replay attacks
- Signature replay vulnerabilities

These tests ensure critical exploit patterns are always detected.

### 5. Pre-Commit Hook (Primary)

**Location**: `.pre-commit-config.yaml` / `scripts/pre-commit-validate.sh`

**This is the primary validation checkpoint.** When you modify detector files and attempt to commit:

1. The hook automatically detects staged changes in `crates/detectors/`
2. Runs regression tests to ensure critical vulnerabilities are still detected
3. Validates against ground truth with `--fail-on-regression`
4. **Blocks the commit if validation fails**

```
$ git commit -m "Tighten reentrancy detector"
Detector files modified - running validation...
  crates/detectors/src/reentrancy.rs

Running regression tests...
✓ Regression tests passed

Validating against ground truth...
✓ Ground truth validation passed

✓ All validation checks passed
[main abc1234] Tighten reentrancy detector
```

**To bypass (not recommended)**:
```bash
git commit --no-verify
```

### 6. CI Integration (Safety Net)

**Location**: `.github/workflows/validate.yml`

Secondary validation that runs on:
- PRs modifying `crates/detectors/**`
- PRs modifying `tests/validation/**`
- PRs modifying `tests/contracts/**`
- Pushes to main

Posts validation metrics as PR comments. Catches issues if pre-commit was bypassed.

## Metrics Explained

| Metric | Formula | Meaning |
|--------|---------|---------|
| **Precision** | TP / (TP + FP) | Of findings reported, what % are real vulnerabilities |
| **Recall** | TP / (TP + FN) | Of known vulnerabilities, what % were detected |
| **F1 Score** | 2 * (P * R) / (P + R) | Harmonic mean of precision and recall |

**Goals**:
- **High Precision** (>85%): Few false positives, findings are trustworthy
- **High Recall** (>90%): Few missed vulnerabilities, comprehensive coverage

## Workflow: Modifying a Detector

### Step 1: Capture Baseline (Before Changes)

```bash
./scripts/validate_detector_change.sh <detector_id>
```

This saves current findings for comparison after your changes.

### Step 2: Make Your Changes

Edit the detector code in `crates/detectors/src/`.

### Step 3: Compare Results

```bash
./scripts/validate_detector_change.sh --compare <detector_id>
```

**Review all removed findings** - Each one must be a confirmed false positive.

### Step 4: Commit

```bash
git add .
git commit -m "Tighten <detector_id> to reduce false positives"
```

**The pre-commit hook automatically:**
- Runs regression tests
- Validates against ground truth
- Blocks commit if validation fails

If the commit is blocked, review the error output and fix any regressions before retrying.

### Step 5: Update Ground Truth (If Needed)

If you confirmed new true/false positives during your review, update `tests/validation/ground_truth.json` and commit the update.

## Adding to Ground Truth

When you verify a finding as true positive or false positive:

1. Edit `tests/validation/ground_truth.json`
2. Add to the appropriate contract section:

**For a true positive (real vulnerability)**:
```json
{
  "detector_id": "reentrancy",
  "line_range": [42, 50],
  "label": "true_positive",
  "severity": "critical",
  "description": "External call before balance update",
  "vulnerability_type": "classic-reentrancy"
}
```

**For a known false positive**:
```json
{
  "detector_id": "reentrancy",
  "line": 75,
  "reason": "CEI pattern correctly followed, ReentrancyGuard used"
}
```

## Troubleshooting

### "Validation failed: Recall below threshold"

Some expected vulnerabilities weren't detected. Check:
1. Did a recent detector change cause a regression?
2. Is the ground truth accurate? Maybe the vulnerability was fixed.
3. Run with `--fail-on-regression` to see exactly which findings are missed.

### "Validation failed: Precision below threshold"

Too many false positives. Check:
1. Are the "false positives" actually vulnerabilities that should be in ground truth?
2. Does the detector need tightening?

### "Contract file not found"

The ground truth references a contract that doesn't exist. Either:
1. The contract was moved/renamed - update ground truth
2. The contract was deleted - remove from ground truth

## Best Practices

1. **Always run validation before committing detector changes**
2. **Review all removed findings** when tightening a detector
3. **Update ground truth** when you confirm true/false positives
4. **Add regression tests** for critical exploit patterns
5. **Keep precision and recall balanced** - don't sacrifice one for the other
