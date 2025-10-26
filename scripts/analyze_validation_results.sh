#!/bin/bash
# Analyze validation results and create detailed reports

set -e

RESULTS_DIR="/Users/pwner/Git/ABS/SolidityDefend/test-results"
LATEST=$(ls -t "${RESULTS_DIR}"/validation_*.log | head -1)
TIMESTAMP=$(basename "${LATEST}" .log | sed 's/validation_//')
INDIVIDUAL_DIR="${RESULTS_DIR}/individual/${TIMESTAMP}"

echo "Analyzing validation results from: ${TIMESTAMP}"
echo "========================================================================"
echo ""

# Summary statistics
echo "## Overall Statistics"
echo ""
total_contracts=0
total_findings=0
critical_total=0
high_total=0
medium_total=0
low_total=0

# Analyze each JSON file
for json_file in $(find "${INDIVIDUAL_DIR}" -name "*.json" -type f); do
    if grep -q '"version"' "${json_file}" 2>/dev/null; then
        total_contracts=$((total_contracts + 1))

        findings=$(grep -o '"detector_id"' "${json_file}" 2>/dev/null | wc -l | tr -d ' ')
        critical=$(grep '"severity": "critical"' "${json_file}" 2>/dev/null | wc -l | tr -d ' ')
        high=$(grep '"severity": "high"' "${json_file}" 2>/dev/null | wc -l | tr -d ' ')
        medium=$(grep '"severity": "medium"' "${json_file}" 2>/dev/null | wc -l | tr -d ' ')
        low=$(grep '"severity": "low"' "${json_file}" 2>/dev/null | wc -l | tr -d ' ')

        total_findings=$((total_findings + findings))
        critical_total=$((critical_total + critical))
        high_total=$((high_total + high))
        medium_total=$((medium_total + medium))
        low_total=$((low_total + low))
    fi
done

echo "  Total Contracts Analyzed: ${total_contracts}"
echo "  Total Findings: ${total_findings}"
echo "  Critical Severity: ${critical_total}"
echo "  High Severity: ${high_total}"
echo "  Medium Severity: ${medium_total}"
echo "  Low Severity: ${low_total}"
echo ""

# Top detectors by frequency
echo "## Top 10 Most Triggered Detectors"
echo ""
find "${INDIVIDUAL_DIR}" -name "*.json" -type f -exec cat {} \; | \
    grep '"detector_id"' | \
    sed 's/.*"detector_id": "\([^"]*\)".*/\1/' | \
    sort | uniq -c | sort -rn | head -10 | \
    awk '{printf "  %3d  %s\n", $1, $2}'
echo ""

# Vulnerable contracts analysis
echo "## Vulnerable Contracts Analysis"
echo ""
for json_file in $(find "${INDIVIDUAL_DIR}" -name "*vulnerable*.json" -o -name "*Vulnerable*.json" | sort); do
    contract_name=$(basename "${json_file}" .json)
    findings=$(grep -o '"detector_id"' "${json_file}" 2>/dev/null | wc -l | tr -d ' ')
    critical=$(grep '"severity": "critical"' "${json_file}" 2>/dev/null | wc -l | tr -d ' ')
    high=$(grep '"severity": "high"' "${json_file}" 2>/dev/null | wc -l | tr -d ' ')
    medium=$(grep '"severity": "medium"' "${json_file}" 2>/dev/null | wc -l | tr -d ' ')
    low=$(grep '"severity": "low"' "${json_file}" 2>/dev/null | wc -l | tr -d ' ')

    if [ "${findings}" -gt 0 ]; then
        printf "  %-50s %3d findings (C:%2d H:%2d M:%2d L:%2d)\n" \
            "${contract_name}" "${findings}" "${critical}" "${high}" "${medium}" "${low}"
    fi
done
echo ""

# Clean contracts analysis
echo "## Clean/Secure Contracts Analysis"
echo ""
for json_file in $(find "${INDIVIDUAL_DIR}" -name "*clean*.json" -o -name "*Clean*.json" -o -name "*Secure*.json" | sort); do
    contract_name=$(basename "${json_file}" .json)
    findings=$(grep -o '"detector_id"' "${json_file}" 2>/dev/null | wc -l | tr -d ' ')
    critical=$(grep '"severity": "critical"' "${json_file}" 2>/dev/null | wc -l | tr -d ' ')
    high=$(grep '"severity": "high"' "${json_file}" 2>/dev/null | wc -l | tr -d ' ')
    medium=$(grep '"severity": "medium"' "${json_file}" 2>/dev/null | wc -l | tr -d ' ')
    low=$(grep '"severity": "low"' "${json_file}" 2>/dev/null | wc -l | tr -d ' ')

    if [ "${critical}" -gt 0 ] || [ "${high}" -gt 0 ]; then
        status="⚠ UNEXPECTED"
    else
        status="✓ PASS"
    fi

    printf "  %-50s %3d findings (C:%2d H:%2d M:%2d L:%2d) %s\n" \
        "${contract_name}" "${findings}" "${critical}" "${high}" "${medium}" "${low}" "${status}"
done
echo ""

# Detection coverage by phase
echo "## Detection Coverage by Phase"
echo ""

echo "  Phase 13: Cross-Chain Bridge Security"
phase13_files=$(find "${INDIVIDUAL_DIR}/cross_chain" -name "*.json" 2>/dev/null | wc -l | tr -d ' ')
phase13_findings=$(find "${INDIVIDUAL_DIR}/cross_chain" -name "*.json" -exec cat {} \; 2>/dev/null | grep -o '"detector_id"' | wc -l | tr -d ' ')
echo "    Contracts: ${phase13_files}, Total Findings: ${phase13_findings}"

echo "  Phase 16: ERC-4626 Vault Security"
phase16_files=$(find "${INDIVIDUAL_DIR}/erc4626_vaults" -name "*.json" 2>/dev/null | wc -l | tr -d ' ')
phase16_findings=$(find "${INDIVIDUAL_DIR}/erc4626_vaults" -name "*.json" -exec cat {} \; 2>/dev/null | grep -o '"detector_id"' | wc -l | tr -d ' ')
echo "    Contracts: ${phase16_files}, Total Findings: ${phase16_findings}"

echo "  2025 Complex Vulnerabilities"
complex_files=$(find "${INDIVIDUAL_DIR}/complex_scenarios/2025_vulnerabilities" -name "*.json" 2>/dev/null | wc -l | tr -d ' ')
complex_findings=$(find "${INDIVIDUAL_DIR}/complex_scenarios/2025_vulnerabilities" -name "*.json" -exec cat {} \; 2>/dev/null | grep -o '"detector_id"' | wc -l | tr -d ' ')
echo "    Contracts: ${complex_files}, Total Findings: ${complex_findings}"

echo ""
echo "========================================================================"
echo "Report complete. Full details in:"
echo "  ${RESULTS_DIR}/summary_${TIMESTAMP}.txt"
echo "  ${RESULTS_DIR}/validation_${TIMESTAMP}.log"
echo "========================================================================"
