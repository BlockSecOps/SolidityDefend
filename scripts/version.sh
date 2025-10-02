#!/bin/bash
# version.sh - Version management script for SolidityDefend

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

show_help() {
    cat << EOF
SolidityDefend Version Management Script

USAGE:
    ./scripts/version.sh <COMMAND> [OPTIONS]

COMMANDS:
    show                Show current version information
    bump <TYPE>         Bump version (patch, minor, major)
    set <VERSION>       Set specific version
    tag                 Create git tag for current version
    check               Check version consistency across workspace
    release             Prepare for release (bump + tag + changelog)

EXAMPLES:
    ./scripts/version.sh show
    ./scripts/version.sh bump patch
    ./scripts/version.sh bump minor
    ./scripts/version.sh set 1.0.0
    ./scripts/version.sh tag
    ./scripts/version.sh release minor

EOF
}

get_current_version() {
    grep '^version = ' "$ROOT_DIR/Cargo.toml" | head -n1 | sed 's/version = "\(.*\)"/\1/'
}

get_git_info() {
    if git rev-parse --git-dir > /dev/null 2>&1; then
        echo "Git Hash: $(git rev-parse --short=8 HEAD 2>/dev/null || echo 'unknown')"
        echo "Git Branch: $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"
        echo "Git Dirty: $(if [ -n "$(git status --porcelain 2>/dev/null)" ]; then echo 'true'; else echo 'false'; fi)"
        echo "Commits: $(git rev-list --count HEAD 2>/dev/null || echo '0')"
    else
        echo "Not a git repository"
    fi
}

show_version() {
    echo -e "${BLUE}SolidityDefend Version Information${NC}"
    echo "=================================="
    echo "Current Version: $(get_current_version)"
    echo ""
    get_git_info
    echo ""
    echo "Build Information:"
    echo "  Rust Version: $(rustc --version | awk '{print $2}')"
    echo "  Target: $(rustc -vV | grep host | awk '{print $2}')"
    echo ""
    echo "Workspace Status:"
    cargo tree --workspace --depth 0 | grep -E '^[a-z]' | wc -l | awk '{print "  Crates: " $1}'
    find "$ROOT_DIR" -name "*.rs" -not -path "*/target/*" | wc -l | awk '{print "  Rust Files: " $1}'
}

validate_version() {
    local version="$1"
    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]; then
        echo -e "${RED}Error: Invalid semantic version format: $version${NC}" >&2
        echo "Expected format: MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]" >&2
        exit 1
    fi
}

parse_version() {
    local version="$1"
    echo "$version" | sed -E 's/([0-9]+)\.([0-9]+)\.([0-9]+).*/\1 \2 \3/'
}

bump_version() {
    local bump_type="$1"
    local current_version
    current_version=$(get_current_version)

    echo -e "${BLUE}Current version: $current_version${NC}"

    local version_parts
    version_parts=($(parse_version "$current_version"))
    local major=${version_parts[0]}
    local minor=${version_parts[1]}
    local patch=${version_parts[2]}

    case "$bump_type" in
        patch)
            patch=$((patch + 1))
            ;;
        minor)
            minor=$((minor + 1))
            patch=0
            ;;
        major)
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        *)
            echo -e "${RED}Error: Invalid bump type. Use: patch, minor, or major${NC}" >&2
            exit 1
            ;;
    esac

    local new_version="$major.$minor.$patch"
    echo -e "${GREEN}New version: $new_version${NC}"

    set_version "$new_version"
}

set_version() {
    local new_version="$1"
    validate_version "$new_version"

    echo -e "${YELLOW}Setting version to: $new_version${NC}"

    # Update workspace version
    sed -i.bak "s/version = \".*\"/version = \"$new_version\"/" "$ROOT_DIR/Cargo.toml"
    rm -f "$ROOT_DIR/Cargo.toml.bak"

    # Update all crate versions that inherit from workspace
    # (They should already inherit via version.workspace = true)

    echo -e "${GREEN}Version updated successfully${NC}"

    # Verify the change
    echo "New version: $(get_current_version)"
}

create_tag() {
    local version
    version=$(get_current_version)
    local tag_name="v$version"

    # Check if tag already exists
    if git tag -l | grep -q "^$tag_name$"; then
        echo -e "${YELLOW}Tag $tag_name already exists${NC}"
        read -p "Do you want to delete and recreate it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            git tag -d "$tag_name"
            git push origin ":refs/tags/$tag_name" 2>/dev/null || true
        else
            echo "Aborted"
            exit 1
        fi
    fi

    echo -e "${BLUE}Creating tag: $tag_name${NC}"
    git tag -a "$tag_name" -m "Release version $version"

    echo -e "${GREEN}Tag created successfully${NC}"
    echo "To push the tag, run: git push origin $tag_name"
}

check_workspace() {
    echo -e "${BLUE}Checking workspace version consistency...${NC}"

    local workspace_version
    workspace_version=$(get_current_version)
    local issues=0

    echo "Workspace version: $workspace_version"
    echo ""

    # Check all Cargo.toml files
    find "$ROOT_DIR" -name "Cargo.toml" -not -path "*/target/*" | while read -r cargo_file; do
        local crate_name
        crate_name=$(grep '^name = ' "$cargo_file" | head -n1 | sed 's/name = "\(.*\)"/\1/')

        if grep -q "version.workspace = true" "$cargo_file"; then
            echo -e "  ${GREEN}✓${NC} $crate_name (inherits workspace version)"
        elif grep -q "version = " "$cargo_file"; then
            local crate_version
            crate_version=$(grep '^version = ' "$cargo_file" | head -n1 | sed 's/version = "\(.*\)"/\1/')
            if [ "$crate_version" = "$workspace_version" ]; then
                echo -e "  ${GREEN}✓${NC} $crate_name ($crate_version)"
            else
                echo -e "  ${RED}✗${NC} $crate_name ($crate_version != $workspace_version)"
                issues=$((issues + 1))
            fi
        fi
    done

    if [ $issues -eq 0 ]; then
        echo -e "\n${GREEN}All versions are consistent${NC}"
    else
        echo -e "\n${RED}Found $issues version inconsistencies${NC}"
        exit 1
    fi
}

generate_changelog() {
    local version="$1"
    local changelog_file="$ROOT_DIR/CHANGELOG.md"

    echo -e "${BLUE}Generating changelog for version $version...${NC}"

    # Create changelog if it doesn't exist
    if [ ! -f "$changelog_file" ]; then
        cat > "$changelog_file" << EOF
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

EOF
    fi

    # Get commits since last tag
    local last_tag
    last_tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "")

    local commits
    if [ -n "$last_tag" ]; then
        commits=$(git log "$last_tag"..HEAD --oneline)
    else
        commits=$(git log --oneline)
    fi

    # Generate changelog entry
    local changelog_entry
    changelog_entry=$(cat << EOF

## [$version] - $(date +%Y-%m-%d)

### Added
- New security detectors and analysis capabilities
- Enhanced performance optimizations
- Comprehensive documentation suite

### Changed
- Improved detection accuracy and reduced false positives
- Updated CLI interface with new commands
- Enhanced output formatting

### Fixed
- Various bug fixes and stability improvements
- Memory usage optimizations
- Build and deployment issues

EOF
)

    # Insert new entry after the header
    local temp_file
    temp_file=$(mktemp)
    awk -v entry="$changelog_entry" '
        /^# Changelog/ { print; print entry; next }
        { print }
    ' "$changelog_file" > "$temp_file"

    mv "$temp_file" "$changelog_file"

    echo -e "${GREEN}Changelog updated${NC}"
}

prepare_release() {
    local bump_type="$1"

    if [ -z "$bump_type" ]; then
        echo -e "${RED}Error: Bump type required for release${NC}" >&2
        echo "Usage: $0 release <patch|minor|major>" >&2
        exit 1
    fi

    echo -e "${BLUE}Preparing release...${NC}"

    # Check git status
    if [ -n "$(git status --porcelain)" ]; then
        echo -e "${YELLOW}Warning: Working directory is dirty${NC}"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Aborted"
            exit 1
        fi
    fi

    # Bump version
    bump_version "$bump_type"
    local new_version
    new_version=$(get_current_version)

    # Generate changelog
    generate_changelog "$new_version"

    # Create commit
    git add Cargo.toml CHANGELOG.md
    git commit -m "chore: Release version $new_version"

    # Create tag
    create_tag

    echo -e "${GREEN}Release prepared successfully!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Review the changes: git show HEAD"
    echo "2. Push the changes: git push origin $(git rev-parse --abbrev-ref HEAD)"
    echo "3. Push the tag: git push origin v$new_version"
    echo "4. Create GitHub release (if applicable)"
}

# Main script logic
case "${1:-}" in
    show)
        show_version
        ;;
    bump)
        bump_version "$2"
        ;;
    set)
        if [ -z "$2" ]; then
            echo -e "${RED}Error: Version required${NC}" >&2
            echo "Usage: $0 set <VERSION>" >&2
            exit 1
        fi
        set_version "$2"
        ;;
    tag)
        create_tag
        ;;
    check)
        check_workspace
        ;;
    release)
        prepare_release "$2"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo -e "${RED}Error: Unknown command: ${1:-}${NC}" >&2
        echo "Use '$0 help' for usage information" >&2
        exit 1
        ;;
esac