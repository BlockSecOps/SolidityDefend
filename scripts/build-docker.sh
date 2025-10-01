#!/bin/bash
set -euo pipefail

# SolidityDefend Docker Build Script
# Builds Docker images for different environments

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Default values
IMAGE_NAME="soliditydefend"
TAG="latest"
PLATFORM="linux/amd64"
BUILD_CONTEXT="."
DOCKERFILE="Dockerfile"
PUSH=false
REGISTRY=""
CACHE_FROM=""
TARGET=""

# Color output functions
red() { echo -e "\033[31m$*\033[0m"; }
green() { echo -e "\033[32m$*\033[0m"; }
yellow() { echo -e "\033[33m$*\033[0m"; }
blue() { echo -e "\033[34m$*\033[0m"; }

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Build Docker images for SolidityDefend

OPTIONS:
    -n, --name NAME         Image name (default: soliditydefend)
    -t, --tag TAG          Image tag (default: latest)
    -p, --platform PLAT    Target platform (default: linux/amd64)
    -r, --registry REG     Container registry prefix
    --push                 Push image after build
    --cache-from IMAGE     Use image as cache source
    --target TARGET        Build specific stage
    --multi-arch           Build for multiple architectures
    --dev                  Build development image
    --ci                   Build for CI environment
    -h, --help             Show this help

EXAMPLES:
    $0                                    # Build basic image
    $0 --tag v1.0.0 --push              # Build and push release
    $0 --dev                             # Build development image
    $0 --multi-arch --registry ghcr.io  # Multi-arch build
    $0 --ci --cache-from cache-image     # CI build with cache

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--name)
            IMAGE_NAME="$2"
            shift 2
            ;;
        -t|--tag)
            TAG="$2"
            shift 2
            ;;
        -p|--platform)
            PLATFORM="$2"
            shift 2
            ;;
        -r|--registry)
            REGISTRY="$2"
            shift 2
            ;;
        --push)
            PUSH=true
            shift
            ;;
        --cache-from)
            CACHE_FROM="$2"
            shift 2
            ;;
        --target)
            TARGET="$2"
            shift 2
            ;;
        --multi-arch)
            PLATFORM="linux/amd64,linux/arm64"
            shift
            ;;
        --dev)
            DOCKERFILE="Dockerfile.dev"
            TAG="dev"
            shift
            ;;
        --ci)
            TAG="ci-${GITHUB_SHA:-$(git rev-parse --short HEAD)}"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            red "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Construct full image name
FULL_IMAGE_NAME="$IMAGE_NAME:$TAG"
if [[ -n "$REGISTRY" ]]; then
    FULL_IMAGE_NAME="$REGISTRY/$FULL_IMAGE_NAME"
fi

# Validate Docker is available
if ! command -v docker &> /dev/null; then
    red "Error: Docker is not installed or not in PATH"
    exit 1
fi

# Check if buildx is available for multi-platform builds
if [[ "$PLATFORM" == *","* ]]; then
    if ! docker buildx version &> /dev/null; then
        red "Error: Docker buildx is required for multi-platform builds"
        exit 1
    fi
    BUILDER="docker buildx build"
    BUILDX_ARGS="--platform $PLATFORM"
    if [[ "$PUSH" == "true" ]]; then
        BUILDX_ARGS="$BUILDX_ARGS --push"
    else
        BUILDX_ARGS="$BUILDX_ARGS --load"
    fi
else
    BUILDER="docker build"
    BUILDX_ARGS="--platform $PLATFORM"
fi

# Prepare build arguments
BUILD_ARGS=()
BUILD_ARGS+=("--file" "$DOCKERFILE")
BUILD_ARGS+=("--tag" "$FULL_IMAGE_NAME")

if [[ -n "$CACHE_FROM" ]]; then
    BUILD_ARGS+=("--cache-from" "$CACHE_FROM")
fi

if [[ -n "$TARGET" ]]; then
    BUILD_ARGS+=("--target" "$TARGET")
fi

# Add build metadata
BUILD_ARGS+=("--label" "org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)")
BUILD_ARGS+=("--label" "org.opencontainers.image.revision=$(git rev-parse HEAD)")
BUILD_ARGS+=("--label" "org.opencontainers.image.version=$TAG")

# Show build information
blue "Building SolidityDefend Docker image"
echo "  Image: $FULL_IMAGE_NAME"
echo "  Platform: $PLATFORM"
echo "  Dockerfile: $DOCKERFILE"
echo "  Context: $BUILD_CONTEXT"
if [[ -n "$TARGET" ]]; then
    echo "  Target: $TARGET"
fi
if [[ -n "$CACHE_FROM" ]]; then
    echo "  Cache from: $CACHE_FROM"
fi
echo

# Execute build
blue "Starting build..."
if [[ "$PLATFORM" == *","* ]]; then
    set -x
    $BUILDER $BUILDX_ARGS "${BUILD_ARGS[@]}" "$BUILD_CONTEXT"
    set +x
else
    set -x
    $BUILDER "${BUILD_ARGS[@]}" $BUILDX_ARGS "$BUILD_CONTEXT"
    set +x

    # Push if requested and not multi-arch
    if [[ "$PUSH" == "true" ]]; then
        blue "Pushing image..."
        docker push "$FULL_IMAGE_NAME"
    fi
fi

green "✓ Build completed successfully"

# Show image information
if [[ "$PUSH" != "true" && "$PLATFORM" != *","* ]]; then
    echo
    blue "Image information:"
    docker images "$FULL_IMAGE_NAME" --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"

    echo
    blue "To run the image:"
    echo "  docker run --rm -v \$(pwd):/workspace $FULL_IMAGE_NAME [args]"

    echo
    blue "To push the image:"
    echo "  docker push $FULL_IMAGE_NAME"
fi