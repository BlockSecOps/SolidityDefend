#!/bin/bash
set -euo pipefail

# Release Script for SolidityDefend
# Handles version bumping, tagging, and release artifact generation

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Color output functions
red() { echo -e "\033[31m$*\033[0m"; }
green() { echo -e "\033[32m$*\033[0m"; }
yellow() { echo -e "\033[33m$*\033[0m"; }
blue() { echo -e "\033[34m$*\033[0m"; }

# Default values
VERSION=""
DRY_RUN=false
SKIP_TESTS=false
SKIP_BUILD=false
PUSH_DOCKER=false
DOCKER_REGISTRY=""

usage() {
    cat << EOF
Usage: $0 [OPTIONS] VERSION

Create a new release of SolidityDefend

ARGUMENTS:
    VERSION               Version number (e.g., 1.0.0, 1.2.3-beta.1)

OPTIONS:
    --dry-run             Show what would be done without making changes
    --skip-tests          Skip running tests
    --skip-build          Skip building release artifacts
    --push-docker         Push Docker images to registry
    --registry REGISTRY   Docker registry for image push
    -h, --help            Show this help

EXAMPLES:
    $0 1.0.0                          # Create release v1.0.0
    $0 --dry-run 1.1.0               # Preview release v1.1.0
    $0 --push-docker 1.0.0           # Create release and push Docker images

ENVIRONMENT VARIABLES:
    DOCKER_REGISTRY       Default Docker registry
    GITHUB_TOKEN          GitHub token for releases (if using GitHub)

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --push-docker)
            PUSH_DOCKER=true
            shift
            ;;
        --registry)
            DOCKER_REGISTRY="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            red "Unknown option: $1"
            usage
            exit 1
            ;;
        *)
            if [[ -z "$VERSION" ]]; then
                VERSION="$1"
            else
                red "Unexpected argument: $1"
                usage
                exit 1
            fi
            shift
            ;;
    esac
done

# Validate version argument
if [[ -z "$VERSION" ]]; then
    red "Error: Version is required"
    usage
    exit 1
fi

# Validate version format (semver)
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]; then
    red "Error: Invalid version format. Use semver (e.g., 1.0.0, 1.2.3-beta.1)"
    exit 1
fi

# Use environment registry if not specified
if [[ -z "$DOCKER_REGISTRY" ]]; then
    DOCKER_REGISTRY="${DOCKER_REGISTRY:-}"
fi

# Helper functions
run_command() {
    local cmd="$1"
    if [[ "$DRY_RUN" == "true" ]]; then
        blue "[DRY RUN] $cmd"
    else
        blue "Running: $cmd"
        eval "$cmd"
    fi
}

check_git_clean() {
    if [[ -n "$(git status --porcelain)" ]]; then
        red "Error: Working directory is not clean. Commit or stash changes first."
        exit 1
    fi
}

check_git_branch() {
    local current_branch=$(git rev-parse --abbrev-ref HEAD)
    if [[ "$current_branch" != "main" && "$current_branch" != "master" ]]; then
        yellow "Warning: Not on main/master branch (current: $current_branch)"
        read -p "Continue? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

update_version_files() {
    local version="$1"

    # Update root Cargo.toml
    run_command "sed -i.bak 's/^version = \".*\"/version = \"$version\"/' Cargo.toml"

    # Update all crate Cargo.toml files
    for cargo_toml in crates/*/Cargo.toml; do
        run_command "sed -i.bak 's/^version = \".*\"/version = \"$version\"/' $cargo_toml"
    done

    # Clean up backup files
    if [[ "$DRY_RUN" == "false" ]]; then
        find . -name "Cargo.toml.bak" -delete
    fi
}

# Pre-flight checks
blue "Starting release process for version $VERSION"

if [[ "$DRY_RUN" == "true" ]]; then
    yellow "DRY RUN MODE - No changes will be made"
fi

# Check required tools
for tool in git cargo; do
    if ! command -v "$tool" &> /dev/null; then
        red "Error: $tool is required but not installed"
        exit 1
    fi
done

# Git checks
check_git_clean
check_git_branch

# Fetch latest changes
run_command "git fetch origin"

# Check if tag already exists
if git tag -l | grep -q "^v$VERSION$"; then
    red "Error: Tag v$VERSION already exists"
    exit 1
fi

# Run tests
if [[ "$SKIP_TESTS" == "false" ]]; then
    blue "Running test suite..."
    run_command "cargo test --all"
    green "✓ All tests passed"
fi

# Update version in files
blue "Updating version to $VERSION..."
update_version_files "$VERSION"

# Update Cargo.lock
run_command "cargo check"

# Build release artifacts
if [[ "$SKIP_BUILD" == "false" ]]; then
    blue "Building release artifacts..."
    run_command "cargo build --release"
    green "✓ Release build completed"
fi

# Commit version changes
run_command "git add Cargo.toml Cargo.lock crates/*/Cargo.toml"
run_command "git commit -m \"chore: bump version to $VERSION\""

# Create git tag
run_command "git tag -a \"v$VERSION\" -m \"Release version $VERSION\""

# Build Docker images
if [[ "$PUSH_DOCKER" == "true" ]] || [[ -n "$DOCKER_REGISTRY" ]]; then
    blue "Building Docker images..."

    if [[ -n "$DOCKER_REGISTRY" ]]; then
        export DOCKER_REGISTRY
        run_command "./scripts/build-docker.sh --tag $VERSION --registry $DOCKER_REGISTRY"
        run_command "./scripts/build-docker.sh --tag latest --registry $DOCKER_REGISTRY"
    else
        run_command "./scripts/build-docker.sh --tag $VERSION"
        run_command "./scripts/build-docker.sh --tag latest"
    fi

    if [[ "$PUSH_DOCKER" == "true" && -n "$DOCKER_REGISTRY" ]]; then
        blue "Pushing Docker images..."
        run_command "docker push $DOCKER_REGISTRY/soliditydefend:$VERSION"
        run_command "docker push $DOCKER_REGISTRY/soliditydefend:latest"
        green "✓ Docker images pushed"
    fi
fi

# Generate changelog entry
CHANGELOG_ENTRY="## [$VERSION] - $(date +%Y-%m-%d)

### Added
- New features and improvements

### Changed
- Updates and modifications

### Fixed
- Bug fixes and corrections

### Security
- Security-related changes
"

if [[ "$DRY_RUN" == "false" ]]; then
    # Prepend to CHANGELOG.md if it exists
    if [[ -f "CHANGELOG.md" ]]; then
        echo "$CHANGELOG_ENTRY" | cat - CHANGELOG.md > temp && mv temp CHANGELOG.md
        git add CHANGELOG.md
        git commit --amend --no-edit
    fi
fi

# Summary
blue "Release summary:"
echo "  Version: $VERSION"
echo "  Tag: v$VERSION"
echo "  Docker images: $(if [[ -n "$DOCKER_REGISTRY" ]]; then echo "$DOCKER_REGISTRY/soliditydefend:$VERSION"; else echo "soliditydefend:$VERSION"; fi)"

if [[ "$DRY_RUN" == "false" ]]; then
    green "✓ Release v$VERSION created successfully!"
    echo
    blue "Next steps:"
    echo "1. Push the changes: git push origin main --tags"
    echo "2. Create GitHub/GitLab release from tag v$VERSION"
    if [[ "$PUSH_DOCKER" == "false" && -n "$DOCKER_REGISTRY" ]]; then
        echo "3. Push Docker images: ./scripts/docker-helper.sh push $VERSION"
    fi
else
    yellow "DRY RUN completed. No changes were made."
fi