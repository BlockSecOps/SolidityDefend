# Docker Versioning Guide

This document outlines the semantic versioning strategy for SolidityDefend Docker images.

## Semantic Versioning

SolidityDefend follows [Semantic Versioning 2.0.0](https://semver.org/) for Docker image tags:

```
MAJOR.MINOR.PATCH
```

- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible functionality additions
- **PATCH**: Backwards-compatible bug fixes

## Tag Strategy

### Production Releases

Each release should have multiple tags:

```bash
# Current version: 1.0.0
docker build -t soliditydefend:1.0.0 \
             -t soliditydefend:1.0 \
             -t soliditydefend:1 \
             -t soliditydefend:latest .
```

**Tag Explanation:**
- `1.0.0` - Full semantic version (immutable)
- `1.0` - Minor version (updated for patches)
- `1` - Major version (updated for minor/patch releases)
- `latest` - Always points to the newest stable release

### Pre-releases

For beta, alpha, and release candidates:

```bash
# Beta releases
docker build -t soliditydefend:1.1.0-beta.1 .
docker build -t soliditydefend:1.1.0-beta.2 .

# Alpha releases
docker build -t soliditydefend:1.2.0-alpha.1 .

# Release candidates
docker build -t soliditydefend:1.1.0-rc.1 .
```

### Development Builds

For development and testing:

```bash
# Development branch
docker build -t soliditydefend:dev .
docker build -t soliditydefend:dev-20251101 .

# Feature branches
docker build -t soliditydefend:feature-zk-proofs .

# Git commit SHA
docker build -t soliditydefend:sha-abc1234 .
```

## Registry Naming

### GitHub Container Registry (GHCR)

```bash
ghcr.io/blocksecops/soliditydefend:1.0.0
ghcr.io/blocksecops/soliditydefend:1.0
ghcr.io/blocksecops/soliditydefend:1
ghcr.io/blocksecops/soliditydefend:latest
```

### Docker Hub

```bash
blocksecops/soliditydefend:1.0.0
blocksecops/soliditydefend:1.0
blocksecops/soliditydefend:1
blocksecops/soliditydefend:latest
```

## Build and Push Script

Example script for building and pushing with proper versioning:

```bash
#!/bin/bash
set -e

VERSION="1.0.0"
MAJOR=$(echo $VERSION | cut -d. -f1)
MINOR=$(echo $VERSION | cut -d. -f1-2)

REGISTRY="ghcr.io/blocksecops"
IMAGE="soliditydefend"

# Build with all tags
docker build \
  -t ${REGISTRY}/${IMAGE}:${VERSION} \
  -t ${REGISTRY}/${IMAGE}:${MINOR} \
  -t ${REGISTRY}/${IMAGE}:${MAJOR} \
  -t ${REGISTRY}/${IMAGE}:latest \
  .

# Push all tags
docker push ${REGISTRY}/${IMAGE}:${VERSION}
docker push ${REGISTRY}/${IMAGE}:${MINOR}
docker push ${REGISTRY}/${IMAGE}:${MAJOR}
docker push ${REGISTRY}/${IMAGE}:latest
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Build and Push Docker

on:
  push:
    tags:
      - 'v*'

jobs:
  docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Docker meta
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: |
            ghcr.io/blocksecops/soliditydefend
          tags: |
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=semver,pattern={{major}}
            type=raw,value=latest,enable={{is_default_branch}}

      - name: Login to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
```

## Version Management

### Reading Version from Cargo.toml

Automatically extract version from `Cargo.toml`:

```bash
VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
docker build -t soliditydefend:${VERSION} .
```

### Using Build Arguments

Pass version as build argument:

```dockerfile
ARG VERSION=dev
LABEL org.opencontainers.image.version="${VERSION}"
```

Build:
```bash
docker build --build-arg VERSION=1.0.0 -t soliditydefend:1.0.0 .
```

## Best Practices

1. **Never overwrite tags**: Once a version tag is pushed, never overwrite it
2. **Use immutable tags in production**: Reference specific versions (e.g., `1.0.0`) not `latest`
3. **Update floating tags**: Keep `latest`, major, and minor tags updated
4. **Pre-release versioning**: Use `-beta`, `-alpha`, `-rc` suffixes for pre-releases
5. **Document breaking changes**: Clearly mark major version bumps
6. **Git tag correlation**: Ensure Docker tags match Git tags (e.g., `v1.0.0`)

## Examples

### User Pull Commands

```bash
# Specific version (recommended for production)
docker pull soliditydefend:1.0.0

# Latest stable
docker pull soliditydefend:latest

# Latest major version 1.x
docker pull soliditydefend:1

# Beta version
docker pull soliditydefend:1.1.0-beta.1
```

### Version Comparison

| Tag | Use Case | Updates |
|-----|----------|---------|
| `1.0.0` | Production deployments requiring stability | Never |
| `1.0` | Pin to minor version, get patches | Patch releases (1.0.1, 1.0.2) |
| `1` | Stay on major version, get features | Minor and patch releases |
| `latest` | Development/testing | All stable releases |
| `dev` | Continuous development | Every commit to main |

## Version History

- **1.0.0** (2025-11-01) - Initial production release with 178 detectors
- **0.16.0** (2025-10-30) - Phase 30 advanced DeFi detectors
- **0.15.0** (2025-10-29) - Complete detector suite
- **0.11.1** (2025-10-27) - Patch release
- **0.11.0** (2025-10-27) - 100 detectors milestone

## Related Documentation

- [Semantic Versioning](https://semver.org/)
- [Docker Tag Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [OCI Image Spec](https://github.com/opencontainers/image-spec/blob/main/annotations.md)
