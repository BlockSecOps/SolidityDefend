#!/bin/bash
set -euo pipefail

# Docker Helper Script for SolidityDefend
# Provides convenient commands for Docker-based development and deployment

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Color output functions
red() { echo -e "\033[31m$*\033[0m"; }
green() { echo -e "\033[32m$*\033[0m"; }
yellow() { echo -e "\033[33m$*\033[0m"; }
blue() { echo -e "\033[34m$*\033[0m"; }

usage() {
    cat << EOF
Usage: $0 COMMAND [OPTIONS]

Docker helper commands for SolidityDefend

COMMANDS:
    build [TAG]           Build production Docker image
    build-dev             Build development Docker image
    run [ARGS...]         Run SolidityDefend in container
    dev                   Start development environment
    shell                 Open shell in development container
    test                  Run tests in container
    ci                    Run CI build in container
    clean                 Clean Docker artifacts
    push [TAG]            Push image to registry
    pull [TAG]            Pull image from registry

EXAMPLES:
    $0 build v1.0.0                    # Build tagged image
    $0 run --help                      # Show SolidityDefend help
    $0 run /workspace/contracts        # Scan contracts directory
    $0 dev                             # Start development environment
    $0 test                            # Run test suite
    $0 ci                              # Run CI build

ENVIRONMENT VARIABLES:
    DOCKER_REGISTRY       Container registry (default: none)
    DOCKER_TAG           Default image tag (default: latest)
    DOCKER_PLATFORM      Build platform (default: linux/amd64)

EOF
}

# Default values
REGISTRY="${DOCKER_REGISTRY:-}"
TAG="${DOCKER_TAG:-latest}"
PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"

# Helper functions
image_name() {
    local tag="${1:-$TAG}"
    if [[ -n "$REGISTRY" ]]; then
        echo "$REGISTRY/soliditydefend:$tag"
    else
        echo "soliditydefend:$tag"
    fi
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        red "Error: Docker is not installed"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        red "Error: Docker daemon is not running"
        exit 1
    fi
}

# Command implementations
cmd_build() {
    local tag="${1:-$TAG}"
    local image=$(image_name "$tag")

    check_docker
    blue "Building Docker image: $image"

    docker build \
        --platform "$PLATFORM" \
        --tag "$image" \
        --label "org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --label "org.opencontainers.image.revision=$(git rev-parse HEAD 2>/dev/null || echo unknown)" \
        --label "org.opencontainers.image.version=$tag" \
        .

    green "✓ Build completed: $image"
}

cmd_build_dev() {
    check_docker
    blue "Building development Docker image"

    docker build \
        --platform "$PLATFORM" \
        --tag "soliditydefend:dev" \
        --file Dockerfile.dev \
        .

    green "✓ Development image built: soliditydefend:dev"
}

cmd_run() {
    local image=$(image_name)
    check_docker

    if ! docker image inspect "$image" &> /dev/null; then
        yellow "Image $image not found, building..."
        cmd_build
    fi

    blue "Running SolidityDefend in container"
    docker run --rm \
        --platform "$PLATFORM" \
        -v "$(pwd):/workspace:ro" \
        "$image" "$@"
}

cmd_dev() {
    check_docker

    if ! docker image inspect "soliditydefend:dev" &> /dev/null; then
        yellow "Development image not found, building..."
        cmd_build_dev
    fi

    blue "Starting development environment"
    docker-compose up -d soliditydefend-dev
    docker-compose exec soliditydefend-dev /bin/bash
}

cmd_shell() {
    check_docker

    if ! docker-compose ps soliditydefend-dev | grep -q "Up"; then
        blue "Starting development container..."
        docker-compose up -d soliditydefend-dev
    fi

    blue "Opening shell in development container"
    docker-compose exec soliditydefend-dev /bin/bash
}

cmd_test() {
    local image=$(image_name)
    check_docker

    if ! docker image inspect "$image" &> /dev/null; then
        yellow "Image $image not found, building..."
        cmd_build
    fi

    blue "Running tests in container"
    docker run --rm \
        --platform "$PLATFORM" \
        -v "$(pwd):/workspace" \
        -e CI=true \
        "$image" \
        sh -c "cd /workspace && cargo test --all"
}

cmd_ci() {
    check_docker
    blue "Running CI build in container"
    docker-compose run --rm soliditydefend-ci
}

cmd_clean() {
    check_docker
    blue "Cleaning Docker artifacts"

    # Stop and remove containers
    docker-compose down --remove-orphans 2>/dev/null || true

    # Remove images
    docker images -q "soliditydefend*" | xargs -r docker rmi -f

    # Remove volumes
    docker volume ls -q | grep soliditydefend | xargs -r docker volume rm

    # Prune build cache
    docker builder prune -f

    green "✓ Docker artifacts cleaned"
}

cmd_push() {
    local tag="${1:-$TAG}"
    local image=$(image_name "$tag")
    check_docker

    if [[ -z "$REGISTRY" ]]; then
        red "Error: DOCKER_REGISTRY environment variable must be set for push"
        exit 1
    fi

    if ! docker image inspect "$image" &> /dev/null; then
        yellow "Image $image not found, building..."
        cmd_build "$tag"
    fi

    blue "Pushing image: $image"
    docker push "$image"
    green "✓ Image pushed: $image"
}

cmd_pull() {
    local tag="${1:-$TAG}"
    local image=$(image_name "$tag")
    check_docker

    if [[ -z "$REGISTRY" ]]; then
        red "Error: DOCKER_REGISTRY environment variable must be set for pull"
        exit 1
    fi

    blue "Pulling image: $image"
    docker pull "$image"
    green "✓ Image pulled: $image"
}

# Main command handling
case "${1:-}" in
    build)
        shift
        cmd_build "$@"
        ;;
    build-dev)
        cmd_build_dev
        ;;
    run)
        shift
        cmd_run "$@"
        ;;
    dev)
        cmd_dev
        ;;
    shell)
        cmd_shell
        ;;
    test)
        cmd_test
        ;;
    ci)
        cmd_ci
        ;;
    clean)
        cmd_clean
        ;;
    push)
        shift
        cmd_push "$@"
        ;;
    pull)
        shift
        cmd_pull "$@"
        ;;
    -h|--help|help)
        usage
        exit 0
        ;;
    "")
        red "Error: No command specified"
        usage
        exit 1
        ;;
    *)
        red "Error: Unknown command: $1"
        usage
        exit 1
        ;;
esac