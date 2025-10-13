#!/bin/bash
# Release readiness validation script
# Ensures all requirements are met before creating a release

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}SolidityDefend Release Readiness Check${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

FAILED=0

# Get current version from Cargo.toml
CURRENT_VERSION=$(grep '^version = ' Cargo.toml | head -1 | cut -d'"' -f2)
echo -e "${BLUE}Current Version: ${CURRENT_VERSION}${NC}"
echo ""

# 1. Check if working directory is clean
echo -e "${YELLOW}1. Checking git status...${NC}"
if [ -z "$(git status --porcelain)" ]; then
    echo -e "${GREEN}✓ Working directory is clean${NC}"
else
    echo -e "${RED}✗ Working directory has uncommitted changes${NC}"
    git status --short
    FAILED=1
fi
echo ""

# 2. Check if on main branch
echo -e "${YELLOW}2. Checking branch...${NC}"
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$CURRENT_BRANCH" = "main" ]; then
    echo -e "${GREEN}✓ On main branch${NC}"
else
    echo -e "${YELLOW}⚠ On branch: ${CURRENT_BRANCH} (should be main for release)${NC}"
fi
echo ""

# 3. Check if CHANGELOG.md has entry for current version
echo -e "${YELLOW}3. Checking CHANGELOG.md...${NC}"
if grep -q "## \[${CURRENT_VERSION}\]" CHANGELOG.md; then
    echo -e "${GREEN}✓ CHANGELOG.md has entry for ${CURRENT_VERSION}${NC}"
else
    echo -e "${RED}✗ CHANGELOG.md missing entry for ${CURRENT_VERSION}${NC}"
    FAILED=1
fi
echo ""

# 4. Check if version tag already exists
echo -e "${YELLOW}4. Checking for existing tag...${NC}"
if git rev-parse "v${CURRENT_VERSION}" >/dev/null 2>&1; then
    echo -e "${RED}✗ Tag v${CURRENT_VERSION} already exists${NC}"
    FAILED=1
else
    echo -e "${GREEN}✓ Tag v${CURRENT_VERSION} does not exist${NC}"
fi
echo ""

# 5. Run full CI validation
echo -e "${YELLOW}5. Running CI validation...${NC}"
if make ci-local > /dev/null 2>&1; then
    echo -e "${GREEN}✓ All CI checks passed${NC}"
else
    echo -e "${RED}✗ CI validation failed${NC}"
    FAILED=1
fi
echo ""

# 6. Check if binary builds
echo -e "${YELLOW}6. Checking binary build...${NC}"
if cargo build --release --bin soliditydefend > /dev/null 2>&1; then
    BINARY_SIZE=$(ls -lh target/release/soliditydefend | awk '{print $5}')
    echo -e "${GREEN}✓ Binary builds successfully (${BINARY_SIZE})${NC}"
else
    echo -e "${RED}✗ Binary build failed${NC}"
    FAILED=1
fi
echo ""

# 7. Check documentation
echo -e "${YELLOW}7. Checking documentation...${NC}"
if [ -f "README.md" ] && [ -f "CHANGELOG.md" ]; then
    echo -e "${GREEN}✓ Documentation files present${NC}"
else
    echo -e "${RED}✗ Missing documentation files${NC}"
    FAILED=1
fi
echo ""

# 8. Security audit
echo -e "${YELLOW}8. Running security audit...${NC}"
if command -v cargo-audit &> /dev/null; then
    if cargo audit > /dev/null 2>&1; then
        echo -e "${GREEN}✓ No security vulnerabilities found${NC}"
    else
        echo -e "${YELLOW}⚠ Security audit found issues (review manually)${NC}"
    fi
else
    echo -e "${YELLOW}⚠ cargo-audit not installed (install with: cargo install cargo-audit)${NC}"
fi
echo ""

# Final result
echo -e "${BLUE}======================================${NC}"
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ Release readiness check passed!${NC}"
    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    echo "1. Review changes: git log --oneline -10"
    echo "2. Create tag: git tag -a v${CURRENT_VERSION} -m \"Release v${CURRENT_VERSION}\""
    echo "3. Push tag: git push origin v${CURRENT_VERSION}"
    echo "4. GitHub Actions will create the release automatically"
    echo -e "${BLUE}======================================${NC}"
    exit 0
else
    echo -e "${RED}✗ Release readiness check failed!${NC}"
    echo -e "${RED}Fix the issues above before creating a release${NC}"
    echo -e "${BLUE}======================================${NC}"
    exit 1
fi
