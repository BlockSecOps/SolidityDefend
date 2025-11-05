#!/usr/bin/env python3
"""
Generate comprehensive detector documentation from source code.

This script parses all detector implementation files in the codebase,
extracts metadata (ID, name, description, severity, categories, CWEs),
and generates/updates the category-based documentation in docs/detectors.
"""

import os
import re
import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Optional

# Category mapping for documentation organization
CATEGORY_DOCS_MAP = {
    "AccessControl": "access-control",
    "Logic": "code-quality",
    "Reentrancy": "reentrancy",
    "Oracle": "oracle",
    "DeFi": "defi",
    "MEV": "mev",
    "Validation": "input-validation",
    "Gas": "gas-optimization",
    "CrossChain": "cross-chain",
    "Upgrades": "upgrades",
    "Tokens": "tokens",
    "AccountAbstraction": "account-abstraction",
    "ZeroKnowledge": "zero-knowledge",
    "Governance": "governance",
    "Restaking": "restaking",
    "EIP": "eips",
    "FlashLoan": "flash-loans"
}

class DetectorInfo:
    """Holds metadata about a detector."""

    def __init__(self):
        self.id: str = ""
        self.name: str = ""
        self.description: str = ""
        self.severity: str = ""
        self.categories: List[str] = []
        self.cwes: Set[int] = set()
        self.fix_suggestions: List[str] = []
        self.source_file: str = ""
        self.vulnerable_patterns: List[str] = []
        self.secure_patterns: List[str] = []

    def primary_category(self) -> str:
        """Get the primary documentation category for this detector."""
        # Special category detection based on detector ID patterns
        detector_id = self.id.lower()

        # Account Abstraction
        if detector_id.startswith('aa-') or detector_id.startswith('erc4337-'):
            return "account-abstraction"

        # Token Standards
        if any(detector_id.startswith(p) for p in ['erc20-', 'erc721-', 'erc777-', 'erc1155-', 'token-']):
            return "tokens"

        # EIP-specific
        if any(detector_id.startswith(p) for p in ['eip7702-', 'erc7683-', 'erc7821-']):
            return "eips"

        # Flash loans
        if 'flashloan' in detector_id or 'flash-loan' in detector_id or 'flashmint' in detector_id:
            return "flash-loans"

        # Zero-knowledge
        if detector_id.startswith('zk-'):
            return "zero-knowledge"

        # Restaking
        if detector_id.startswith('restaking-') or detector_id.startswith('lrt-') or detector_id.startswith('avs-'):
            return "restaking"

        # MEV
        if 'mev-' in detector_id or 'sandwich' in detector_id or 'frontrun' in detector_id or 'backrun' in detector_id:
            return "mev"

        # Upgrades
        if any(k in detector_id for k in ['upgrade', 'proxy', 'diamond-', 'metamorphic', 'storage-layout']):
            return "upgrades"

        # Cross-chain
        if any(k in detector_id for k in ['bridge-', 'cross-chain', 'l2-', 'cross-rollup', 'celestia', 'rollup']):
            return "cross-chain"

        # Governance
        if 'governance' in detector_id or detector_id in ['delegation-loop', 'weak-commit-reveal', 'multisig-bypass']:
            return "governance"

        # Gas optimization
        if any(k in detector_id for k in ['gas-', 'inefficient', 'excessive-gas', 'redundant']):
            return "gas-optimization"

        # Reentrancy
        if 'reentrancy' in detector_id or detector_id in ['readonly-reentrancy', 'classic-reentrancy']:
            return "reentrancy"

        # Oracle
        if 'oracle' in detector_id or 'price-' in detector_id:
            return "oracle"

        # Input validation
        if any(k in detector_id for k in ['validation', 'input', 'zero-address', 'array-', 'parameter-']):
            return "input-validation"

        # DeFi
        if any(k in detector_id for k in ['defi-', 'amm-', 'vault-', 'lending-', 'liquidity-', 'slippage', 'yield-', 'jit-']):
            return "defi"

        # Access Control
        if any(k in detector_id for k in ['access-', 'role-', 'privilege-', 'guardian-', 'timelock', 'multirole']):
            return "access-control"

        # Fallback to category-based detection
        if not self.categories:
            return "code-quality"  # default

        first_cat = self.categories[0]
        return CATEGORY_DOCS_MAP.get(first_cat, "code-quality")

def extract_detectors_from_file(file_path: str) -> List[DetectorInfo]:
    """Extract all detector information from a Rust source file (may contain multiple detectors)."""
    detectors = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return detectors

    source_file = os.path.relpath(file_path, os.path.dirname(os.path.dirname(file_path)))

    # Find all BaseDetector::new blocks in the file
    # Handle both .to_string() and .to_string().to_string() patterns
    base_detector_pattern = r'BaseDetector::new\(\s*DetectorId(?:::new)?\(?"([^"]+)"(?:\.to_string\(\))?\)?,\s*"([^"]+)"\.to_string\(\),\s*"([^"]*)"\s*\.to_string\(\)(?:\s*\.to_string\(\))?,\s*vec!\[(.*?)\],\s*Severity::(Critical|High|Medium|Low|Info)'

    for match in re.finditer(base_detector_pattern, content, re.DOTALL):
        info = DetectorInfo()
        info.source_file = source_file
        info.id = match.group(1)
        info.name = match.group(2)
        info.description = match.group(3)
        categories_str = match.group(4)
        info.severity = match.group(5)

        # Extract categories from vec![] content
        cat_pattern = r'DetectorCategory::(\w+)'
        info.categories = re.findall(cat_pattern, categories_str)

        # Extract CWEs and fix suggestions for this specific detector
        # Try to find them in the detector's impl block
        detector_id = info.id

        # Find CWEs near this detector ID
        id_pos = match.start()
        # Look in the next 5000 characters for CWEs related to this detector
        local_content = content[id_pos:id_pos+5000]
        cwe_pattern = r'\.with_cwe\((\d+)\)'
        cwes = re.findall(cwe_pattern, local_content)
        info.cwes = set(int(cwe) for cwe in cwes[:15])  # Limit to first 15 CWEs

        # Extract fix suggestions
        fix_pattern = r'\.with_fix_suggestion\(\s*(?:format!\()?["\']([^"\']+)["\']'
        fixes = re.findall(fix_pattern, local_content, re.DOTALL)
        info.fix_suggestions = [fix.replace('\\n', ' ').replace('  ', ' ').strip() for fix in fixes[:5]]

        # Extract vulnerable patterns
        vuln_pattern = r'// Pattern \d+: ([^\n]+)'
        info.vulnerable_patterns = re.findall(vuln_pattern, local_content)

        detectors.append(info)

    # If no detectors found with BaseDetector pattern, try legacy Detector trait pattern
    if not detectors:
        detectors.extend(extract_legacy_detectors(content, source_file))

    return detectors

def extract_legacy_detectors(content: str, source_file: str) -> List[DetectorInfo]:
    """Extract detectors using the old Detector trait implementation pattern."""
    detectors = []

    # Find all DetectorId definitions in the file (without .to_string() - old pattern)
    id_pattern = r'fn\s+id\s*\(\s*&\s*self\s*\)\s*->\s*DetectorId\s*{\s*DetectorId\(["\']([^"\']+)["\']\s*\.to_string\(\)\s*\)\s*}'
    id_matches = re.finditer(id_pattern, content)

    for id_match in id_matches:
        info = DetectorInfo()
        info.source_file = source_file
        info.id = id_match.group(1)

        # Search backwards and forwards from the ID to find associated methods
        start_pos = max(0, id_match.start() - 1000)
        end_pos = min(len(content), id_match.end() + 3000)
        context = content[start_pos:end_pos]

        # Extract name
        name_match = re.search(r'fn\s+name\s*\(\s*&\s*self\s*\)\s*->\s*&str\s*{\s*["\']([^"\']+)["\']', context)
        if name_match:
            info.name = name_match.group(1)
        else:
            info.name = info.id.replace('-', ' ').title()

        # Extract description
        desc_match = re.search(r'fn\s+description\s*\(\s*&\s*self\s*\)\s*->\s*&str\s*{\s*["\']([^"\']+)["\']', context)
        if desc_match:
            info.description = desc_match.group(1)

        # Extract severity
        severity_match = re.search(r'fn\s+default_severity.*?Severity::(Critical|High|Medium|Low|Info)', context, re.DOTALL)
        if severity_match:
            info.severity = severity_match.group(1)

        # Extract categories
        cat_match = re.search(r'fn\s+categories.*?vec!\[(.*?)\]', context, re.DOTALL)
        if cat_match:
            cat_pattern = r'DetectorCategory::(\w+)'
            info.categories = re.findall(cat_pattern, cat_match.group(1))

        detectors.append(info)

    return detectors

def generate_detector_section(detector: DetectorInfo) -> str:
    """Generate markdown section for a single detector."""
    md = f"## {detector.name}\n\n"
    md += f"**ID:** `{detector.id}`  \n"
    md += f"**Severity:** {detector.severity}  \n"

    if detector.categories:
        cat_str = ", ".join(detector.categories)
        md += f"**Categories:** {cat_str}  \n"

    if detector.cwes:
        cwe_str = ", ".join(f"CWE-{cwe}" for cwe in sorted(detector.cwes))
        md += f"**CWE:** {cwe_str}  \n"

    md += "\n### Description\n\n"
    if detector.description:
        md += f"{detector.description}\n\n"
    else:
        md += "*No description available.*\n\n"

    if detector.vulnerable_patterns:
        md += "### Vulnerable Patterns\n\n"
        for pattern in detector.vulnerable_patterns:
            md += f"- {pattern}\n"
        md += "\n"

    if detector.fix_suggestions:
        md += "### Remediation\n\n"
        for fix in detector.fix_suggestions:
            # Clean up the fix suggestion formatting
            clean_fix = fix.replace("\\n", " ").replace("  ", " ").strip()
            md += f"- {clean_fix}\n"
        md += "\n"

    md += "### Source\n\n"
    md += f"`{detector.source_file}`\n\n"
    md += "---\n\n"

    return md

def group_detectors_by_category(detectors: List[DetectorInfo]) -> Dict[str, List[DetectorInfo]]:
    """Group detectors by their primary documentation category."""
    grouped = defaultdict(list)
    for detector in detectors:
        category = detector.primary_category()
        grouped[category].append(detector)

    # Sort detectors within each category by ID
    for category in grouped:
        grouped[category].sort(key=lambda d: d.id)

    return dict(grouped)

def generate_category_readme(category: str, detectors: List[DetectorInfo]) -> str:
    """Generate README content for a detector category."""
    # Friendly category names
    category_names = {
        "access-control": "Access Control Detectors",
        "account-abstraction": "Account Abstraction Detectors",
        "code-quality": "Code Quality Detectors",
        "cross-chain": "Cross-Chain Security Detectors",
        "defi": "DeFi Protocol Detectors",
        "eips": "EIP-Specific Detectors",
        "flash-loans": "Flash Loan Detectors",
        "gas-optimization": "Gas Optimization Detectors",
        "governance": "Governance Security Detectors",
        "input-validation": "Input Validation Detectors",
        "mev": "MEV Protection Detectors",
        "oracle": "Oracle Security Detectors",
        "reentrancy": "Reentrancy Detectors",
        "restaking": "Restaking Security Detectors",
        "tokens": "Token Standard Detectors",
        "upgrades": "Upgrade Security Detectors",
        "zero-knowledge": "Zero-Knowledge Proof Detectors"
    }

    category_name = category_names.get(category, category.replace("-", " ").title() + " Detectors")

    md = f"# {category_name}\n\n"
    md += f"**Total:** {len(detectors)} detectors\n\n"
    md += "---\n\n"

    for detector in detectors:
        md += generate_detector_section(detector)

    return md

def main():
    """Main function to generate all detector documentation."""
    repo_root = Path(__file__).parent.parent
    detectors_src = repo_root / "crates" / "detectors" / "src"
    docs_dir = repo_root / "docs" / "detectors"

    print("🔍 Scanning detector source files...")

    # Find all detector implementation files
    detector_files = []
    for root, dirs, files in os.walk(detectors_src):
        for file in files:
            # Include all .rs files, only skip core framework files
            if file.endswith('.rs') and file not in ['lib.rs', 'detector.rs', 'registry.rs', 'types.rs', 'utils.rs', 'confidence.rs']:
                file_path = os.path.join(root, file)
                detector_files.append(file_path)

    print(f"📁 Found {len(detector_files)} detector files")

    # Extract detector information
    detectors = []
    for file_path in detector_files:
        file_detectors = extract_detectors_from_file(file_path)
        if file_detectors:
            for info in file_detectors:
                detectors.append(info)
                print(f"  ✓ {info.id}")
        else:
            # Only warn if it's likely a detector file (not a utility module)
            basename = os.path.basename(file_path)
            if basename not in ['mod.rs', 'classification.rs', 'analyzer.rs', 'patterns.rs']:
                print(f"  ⚠ No detectors found in {file_path}")

    print(f"\n📊 Extracted {len(detectors)} detector definitions")

    # Group by category
    grouped = group_detectors_by_category(detectors)
    print(f"📋 Grouped into {len(grouped)} categories")

    # Generate documentation for each category
    print("\n📝 Generating documentation...")
    for category, category_detectors in grouped.items():
        category_dir = docs_dir / category
        category_dir.mkdir(parents=True, exist_ok=True)

        readme_path = category_dir / "README.md"
        content = generate_category_readme(category, category_detectors)

        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"  ✓ {category}/README.md ({len(category_detectors)} detectors)")

    # Generate summary statistics
    print("\n📈 Summary:")
    print(f"  Total detectors documented: {len(detectors)}")
    print(f"  Categories: {len(grouped)}")
    print(f"  Critical severity: {sum(1 for d in detectors if d.severity == 'Critical')}")
    print(f"  High severity: {sum(1 for d in detectors if d.severity == 'High')}")
    print(f"  Medium severity: {sum(1 for d in detectors if d.severity == 'Medium')}")
    print(f"  Low severity: {sum(1 for d in detectors if d.severity == 'Low')}")

    print("\n✅ Documentation generation complete!")

if __name__ == "__main__":
    main()
