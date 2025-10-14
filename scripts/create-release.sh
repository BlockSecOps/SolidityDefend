#!/usr/bin/env bash
# Local Release Creation Script for SolidityDefend
# Creates GitHub release with binaries built locally

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

# Configuration
VERSION="${1:-$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')}"
TAG="v${VERSION}"
BINARY_NAME="soliditydefend"
BUILD_DIR="target/release-builds"
RELEASE_DIR="releases/v${VERSION}"

info "Creating release v${VERSION} for SolidityDefend"
echo ""

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    error "GitHub CLI (gh) is required. Install from: https://cli.github.com/"
fi

# Check if binaries exist
if [ ! -d "${BUILD_DIR}" ] || [ -z "$(ls -A ${BUILD_DIR})" ]; then
    error "No binaries found in ${BUILD_DIR}/. Run ./scripts/build-release.sh first."
fi

# Create release directory
mkdir -p "${RELEASE_DIR}"

# Create archives for each binary
info "Creating release archives..."
echo ""

for binary in "${BUILD_DIR}"/${BINARY_NAME}-*; do
    if [ -f "${binary}" ]; then
        platform=$(basename "${binary}" | sed "s/${BINARY_NAME}-//")
        archive_name="${BINARY_NAME}-${TAG}-${platform}"

        info "Creating archive for ${platform}..."

        # Create temporary directory
        temp_dir=$(mktemp -d)
        cp "${binary}" "${temp_dir}/${BINARY_NAME}"

        # Create archive
        cd "${temp_dir}"
        if [[ "${platform}" == *"windows"* ]]; then
            # Windows: create zip
            zip -q "${archive_name}.zip" "${BINARY_NAME}"
            mv "${archive_name}.zip" "${OLDPWD}/${RELEASE_DIR}/"
            success "Created ${archive_name}.zip"
        else
            # Unix: create tar.gz
            tar czf "${archive_name}.tar.gz" "${BINARY_NAME}"
            mv "${archive_name}.tar.gz" "${OLDPWD}/${RELEASE_DIR}/"
            success "Created ${archive_name}.tar.gz"
        fi
        cd "${OLDPWD}"

        # Cleanup
        rm -rf "${temp_dir}"
    fi
done

echo ""

# Generate SHA256 checksums
info "Generating SHA256 checksums..."
cd "${RELEASE_DIR}"
sha256sum * > SHA256SUMS.txt 2>/dev/null || shasum -a 256 * > SHA256SUMS.txt
success "Created SHA256SUMS.txt"
cd "${OLDPWD}"

echo ""
info "Release files:"
ls -lh "${RELEASE_DIR}/"

echo ""

# Extract changelog for this version
info "Extracting changelog..."
CHANGELOG_FILE="CHANGELOG.md"
RELEASE_NOTES_FILE="${RELEASE_DIR}/release_notes.md"

if [ -f "${CHANGELOG_FILE}" ]; then
    # Extract section for this version
    if grep -q "\[${VERSION}\]" "${CHANGELOG_FILE}"; then
        sed -n "/\[${VERSION}\]/,/\[.*\]/{/\[.*\]/!p;}" "${CHANGELOG_FILE}" > "${RELEASE_NOTES_FILE}"
        success "Extracted changelog from CHANGELOG.md"
    else
        warning "Version ${VERSION} not found in CHANGELOG.md"
        echo "Release ${TAG}" > "${RELEASE_NOTES_FILE}"
        echo "" >> "${RELEASE_NOTES_FILE}"
        echo "See CHANGELOG.md for details." >> "${RELEASE_NOTES_FILE}"
    fi
else
    warning "CHANGELOG.md not found"
    echo "Release ${TAG}" > "${RELEASE_NOTES_FILE}"
    echo "" >> "${RELEASE_NOTES_FILE}"
    echo "100 comprehensive security detectors for Solidity smart contracts." >> "${RELEASE_NOTES_FILE}"
fi

echo ""

# Create or check for git tag
info "Checking git tag..."
if git rev-parse "${TAG}" >/dev/null 2>&1; then
    warning "Tag ${TAG} already exists"
    read -p "Do you want to delete and recreate it? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        git tag -d "${TAG}"
        git push origin ":${TAG}" 2>/dev/null || true
        info "Deleted existing tag"
    else
        info "Using existing tag"
    fi
fi

if ! git rev-parse "${TAG}" >/dev/null 2>&1; then
    info "Creating git tag ${TAG}..."
    git tag -a "${TAG}" -m "Release ${TAG}"
    success "Created tag ${TAG}"

    read -p "Push tag to GitHub? (Y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        git push origin "${TAG}"
        success "Pushed tag to GitHub"
    fi
fi

echo ""

# Create GitHub release
info "Creating GitHub release..."
echo ""

read -p "Create GitHub release now? (Y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    # Check if release already exists
    if gh release view "${TAG}" &>/dev/null; then
        warning "Release ${TAG} already exists"
        read -p "Delete and recreate? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            gh release delete "${TAG}" -y
            info "Deleted existing release"
        else
            info "Keeping existing release, will add/update assets"
        fi
    fi

    # Create or update release
    if ! gh release view "${TAG}" &>/dev/null; then
        gh release create "${TAG}" \
            --title "SolidityDefend ${TAG}" \
            --notes-file "${RELEASE_NOTES_FILE}" \
            "${RELEASE_DIR}"/*
    else
        # Upload assets to existing release
        gh release upload "${TAG}" "${RELEASE_DIR}"/* --clobber
    fi

    success "GitHub release created/updated!"
    echo ""
    info "Release URL: https://github.com/$(git remote get-url origin | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/releases/tag/${TAG}"
else
    info "Skipped GitHub release creation"
    echo ""
    info "To create manually later:"
    echo "  gh release create ${TAG} --title \"SolidityDefend ${TAG}\" --notes-file ${RELEASE_NOTES_FILE} ${RELEASE_DIR}/*"
fi

echo ""

# Update Homebrew formula
info "Updating Homebrew formula..."
FORMULA_FILE="Formula/soliditydefend.rb"

if [ -f "${FORMULA_FILE}" ]; then
    # Calculate SHA256 for each platform
    for archive in "${RELEASE_DIR}"/*.tar.gz "${RELEASE_DIR}"/*.zip; do
        if [ -f "${archive}" ]; then
            filename=$(basename "${archive}")
            sha256=$(shasum -a 256 "${archive}" | awk '{print $1}')

            # Update formula based on platform
            if [[ "${filename}" == *"x86_64-apple-darwin"* ]]; then
                sed -i.bak "s/REPLACE_WITH_ACTUAL_SHA256_X86/${sha256}/g" "${FORMULA_FILE}"
                info "Updated x86_64 macOS SHA256"
            elif [[ "${filename}" == *"aarch64-apple-darwin"* ]]; then
                sed -i.bak "s/REPLACE_WITH_ACTUAL_SHA256_ARM64/${sha256}/g" "${FORMULA_FILE}"
                info "Updated ARM64 macOS SHA256"
            elif [[ "${filename}" == *"x86_64-unknown-linux-gnu"* ]]; then
                sed -i.bak "s/REPLACE_WITH_ACTUAL_SHA256_LINUX/${sha256}/g" "${FORMULA_FILE}"
                info "Updated Linux SHA256"
            fi
        fi
    done

    # Update version
    sed -i.bak "s/version \".*\"/version \"${VERSION}\"/g" "${FORMULA_FILE}"

    # Remove backup files
    rm -f "${FORMULA_FILE}.bak"

    success "Updated Homebrew formula"
    echo ""
    info "To publish to Homebrew tap:"
    echo "  git add ${FORMULA_FILE}"
    echo "  git commit -m 'chore: update formula to ${TAG}'"
    echo "  git push"
else
    warning "Homebrew formula not found at ${FORMULA_FILE}"
fi

echo ""
success "Release ${TAG} created successfully! 🎉"
echo ""
info "What's next:"
echo "  1. Test downloads from GitHub releases"
echo "  2. Test installation script: curl -sSfL https://raw.githubusercontent.com/.../install.sh | bash"
echo "  3. Update Homebrew tap if you have one"
echo "  4. Announce the release!"
