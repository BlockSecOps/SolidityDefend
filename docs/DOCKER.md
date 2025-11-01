# Docker Guide for SolidityDefend

This guide covers running SolidityDefend in Docker containers for development, CI/CD, and production use cases.

## Table of Contents

- [Quick Start](#quick-start)
- [Building the Image](#building-the-image)
- [Running Containers](#running-containers)
- [Docker Compose](#docker-compose)
- [Volume Mounts](#volume-mounts)
- [Configuration](#configuration)
- [CI/CD Integration](#cicd-integration)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### Pull and Run (Coming Soon)

Once published to a container registry:

```bash
# Pull the latest image
docker pull ghcr.io/blocksecops/soliditydefend:latest

# Run on a local contract
docker run --rm -v $(pwd):/workspace ghcr.io/blocksecops/soliditydefend:latest contract.sol
```

### Build and Run Locally

```bash
# Build the image
docker build -t soliditydefend:local .

# Analyze a contract
docker run --rm -v $(pwd):/workspace soliditydefend:local contract.sol
```

---

## Building the Image

### Production Build

Build an optimized production image:

```bash
docker build -t soliditydefend:latest .
```

The build uses a multi-stage approach:
1. **Builder stage**: Compiles the Rust application with all dependencies
2. **Runtime stage**: Creates a minimal Debian-based image (~200MB) with only the binary

### Build Options

**Specify Rust version:**
```bash
docker build --build-arg RUST_VERSION=1.75 -t soliditydefend:latest .
```

**Build with cache disabled:**
```bash
docker build --no-cache -t soliditydefend:latest .
```

**Build for specific platform:**
```bash
# For ARM64 (Apple Silicon, ARM servers)
docker build --platform linux/arm64 -t soliditydefend:arm64 .

# For AMD64 (Intel/AMD processors)
docker build --platform linux/amd64 -t soliditydefend:amd64 .
```

### Development Build

For development with faster rebuild times:

```bash
docker build -f Dockerfile.dev -t soliditydefend:dev .
```

---

## Running Containers

### Basic Usage

**Analyze a single file:**
```bash
docker run --rm -v $(pwd):/workspace soliditydefend:latest contract.sol
```

**Analyze a directory:**
```bash
docker run --rm -v $(pwd):/workspace soliditydefend:latest contracts/
```

**Analyze with glob patterns:**
```bash
docker run --rm -v $(pwd):/workspace soliditydefend:latest "contracts/**/*.sol"
```

### Output Formats

**JSON output to file:**
```bash
docker run --rm -v $(pwd):/workspace \
  soliditydefend:latest \
  -f json -o results.json contracts/
```

**Console output with severity filter:**
```bash
docker run --rm -v $(pwd):/workspace \
  soliditydefend:latest \
  -s high contracts/Vault.sol
```

### Interactive Shell

Run an interactive shell inside the container:

```bash
docker run --rm -it -v $(pwd):/workspace \
  --entrypoint /bin/bash \
  soliditydefend:latest
```

Then run commands inside:
```bash
soliditydefend --list-detectors
soliditydefend contract.sol
```

### Environment Variables

**Set log level:**
```bash
docker run --rm -v $(pwd):/workspace \
  -e RUST_LOG=debug \
  soliditydefend:latest contract.sol
```

**Enable backtrace:**
```bash
docker run --rm -v $(pwd):/workspace \
  -e RUST_BACKTRACE=1 \
  soliditydefend:latest contract.sol
```

---

## Docker Compose

### Quick Start with Docker Compose

The project includes a `docker-compose.yml` for common scenarios:

```bash
# Build all services
docker-compose build

# Analyze contracts (production)
docker-compose run --rm soliditydefend contracts/

# Development environment
docker-compose run --rm soliditydefend-dev bash
```

### Production Service

```yaml
version: '3.8'

services:
  soliditydefend:
    image: soliditydefend:latest
    volumes:
      - ./contracts:/workspace:ro
      - soliditydefend-cache:/home/soliditydefend/.cache
    environment:
      - RUST_LOG=info
    command: ["contracts/", "-f", "json", "-o", "results.json"]

volumes:
  soliditydefend-cache:
```

### CI/CD Service

```yaml
version: '3.8'

services:
  soliditydefend-ci:
    image: soliditydefend:latest
    volumes:
      - ./contracts:/workspace:ro
    environment:
      - CI=true
    command: ["--exit-code-level", "high", "contracts/"]
```

---

## Volume Mounts

### Read-Only Mounts

Mount your contracts directory as read-only for security:

```bash
docker run --rm -v $(pwd)/contracts:/workspace:ro \
  soliditydefend:latest .
```

### Cache Persistence

Persist the cache between runs:

```bash
docker run --rm \
  -v $(pwd):/workspace \
  -v soliditydefend-cache:/home/soliditydefend/.cache \
  soliditydefend:latest contracts/
```

### Output Directory

Mount a specific output directory:

```bash
docker run --rm \
  -v $(pwd)/contracts:/workspace/contracts:ro \
  -v $(pwd)/reports:/workspace/reports \
  soliditydefend:latest \
  -f json -o reports/security.json contracts/
```

---

## Configuration

### Using Configuration Files

Mount your `.soliditydefend.yml` configuration:

```bash
docker run --rm \
  -v $(pwd):/workspace \
  -v $(pwd)/.soliditydefend.yml:/workspace/.soliditydefend.yml:ro \
  soliditydefend:latest contracts/
```

### Generate Configuration

Generate a config template:

```bash
docker run --rm -v $(pwd):/workspace \
  soliditydefend:latest --init-config
```

### Custom Configuration Path

Specify a different config file:

```bash
docker run --rm -v $(pwd):/workspace \
  soliditydefend:latest -c custom-config.yml contracts/
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build SolidityDefend
        run: docker build -t soliditydefend:ci .

      - name: Run Security Scan
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace \
            soliditydefend:ci \
            -f json -o security-report.json contracts/

      - name: Check for Critical Issues
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace \
            soliditydefend:ci \
            --exit-code-level high contracts/

      - name: Upload Results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-report
          path: security-report.json
```

### GitLab CI

```yaml
security_scan:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t soliditydefend:ci .
    - docker run --rm -v $CI_PROJECT_DIR:/workspace soliditydefend:ci -f json -o security-report.json contracts/
    - docker run --rm -v $CI_PROJECT_DIR:/workspace soliditydefend:ci --exit-code-level high contracts/
  artifacts:
    reports:
      json: security-report.json
    when: always
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'docker build -t soliditydefend:${BUILD_NUMBER} .'
            }
        }
        stage('Security Scan') {
            steps {
                sh '''
                    docker run --rm \
                      -v ${WORKSPACE}:/workspace \
                      soliditydefend:${BUILD_NUMBER} \
                      -f json -o security-report.json contracts/
                '''
            }
        }
        stage('Quality Gate') {
            steps {
                sh '''
                    docker run --rm \
                      -v ${WORKSPACE}:/workspace \
                      soliditydefend:${BUILD_NUMBER} \
                      --exit-code-level high contracts/
                '''
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'security-report.json', allowEmptyArchive: true
        }
    }
}
```

---

## Advanced Usage

### Multi-Platform Builds

Build for multiple architectures:

```bash
# Enable BuildKit
export DOCKER_BUILDKIT=1

# Create a builder instance
docker buildx create --name multiarch --use

# Build for multiple platforms
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t soliditydefend:latest \
  --push \
  .
```

### Resource Limits

Limit container resources:

```bash
docker run --rm \
  --memory=2g \
  --cpus=2 \
  -v $(pwd):/workspace \
  soliditydefend:latest contracts/
```

### Network Access

For URL-based analysis with Etherscan API:

```bash
docker run --rm \
  -v $(pwd):/workspace \
  -e ETHERSCAN_API_KEY=your_key_here \
  soliditydefend:latest \
  --from-url https://etherscan.io/address/0x1234...
```

### Custom Entrypoint

Override the entrypoint for debugging:

```bash
docker run --rm -it \
  -v $(pwd):/workspace \
  --entrypoint /bin/bash \
  soliditydefend:latest
```

### Container as a Service

Run as a long-lived service:

```bash
docker run -d \
  --name soliditydefend-service \
  -v $(pwd):/workspace \
  --entrypoint tail \
  soliditydefend:latest -f /dev/null

# Execute analysis
docker exec soliditydefend-service soliditydefend contracts/

# Clean up
docker stop soliditydefend-service
docker rm soliditydefend-service
```

---

## Troubleshooting

### Permission Issues

**Problem**: Permission denied errors when writing output files.

**Solution**: Run with matching user ID:

```bash
docker run --rm \
  -v $(pwd):/workspace \
  --user $(id -u):$(id -g) \
  soliditydefend:latest contracts/
```

Or create a custom Dockerfile:

```dockerfile
FROM soliditydefend:latest
USER root
RUN usermod -u 1000 soliditydefend && groupmod -g 1000 soliditydefend
USER soliditydefend
```

### Large Projects

**Problem**: Build timeout or memory issues with large projects.

**Solution**: Increase Docker resources in Docker Desktop settings or:

```bash
docker run --rm \
  --memory=4g \
  --memory-swap=8g \
  -v $(pwd):/workspace \
  soliditydefend:latest contracts/
```

### Cache Issues

**Problem**: Stale cache causing incorrect results.

**Solution**: Clear the cache:

```bash
docker run --rm -v $(pwd):/workspace \
  soliditydefend:latest --clear-cache

# Or rebuild without cache
docker build --no-cache -t soliditydefend:latest .
```

### Slow Builds

**Problem**: Docker builds take too long.

**Solution**: Use BuildKit and layer caching:

```bash
DOCKER_BUILDKIT=1 docker build -t soliditydefend:latest .
```

Or use the development Dockerfile for faster rebuilds:

```bash
docker build -f Dockerfile.dev -t soliditydefend:dev .
```

### Network Issues

**Problem**: Cannot access URLs or download dependencies.

**Solution**: Check Docker network settings:

```bash
docker run --rm --network host -v $(pwd):/workspace \
  soliditydefend:latest --from-url https://etherscan.io/...
```

### Debugging

**Problem**: Need to debug issues inside the container.

**Solution**: Run with verbose logging:

```bash
docker run --rm \
  -v $(pwd):/workspace \
  -e RUST_LOG=trace \
  -e RUST_BACKTRACE=full \
  soliditydefend:latest contracts/
```

Or get a shell:

```bash
docker run --rm -it \
  -v $(pwd):/workspace \
  --entrypoint /bin/bash \
  soliditydefend:latest

# Then run with debugging
RUST_LOG=debug soliditydefend contracts/
```

---

## Image Size Optimization

The production Dockerfile uses several techniques to minimize image size:

1. **Multi-stage builds**: Separate build and runtime stages
2. **Slim base images**: Uses `debian:bullseye-slim` (~80MB)
3. **Binary stripping**: Removes debug symbols with `strip`
4. **Minimal dependencies**: Only essential runtime libraries

Final image size: **~200MB** (vs ~2GB if built in a single stage)

### Size Breakdown

```bash
# Check image size
docker images soliditydefend:latest

# Inspect layers
docker history soliditydefend:latest
```

---

## Security Best Practices

1. **Run as non-root user**: The Dockerfile creates a dedicated `soliditydefend` user
2. **Read-only mounts**: Mount source code as read-only (`:ro`) when possible
3. **Minimal runtime**: Only includes necessary runtime dependencies
4. **Regular updates**: Rebuild images regularly to get security updates
5. **Scan images**: Use tools like `docker scan` or Trivy:

```bash
docker scan soliditydefend:latest
```

---

## Container Registry Publishing

### GitHub Container Registry (GHCR)

```bash
# Login
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Tag
docker tag soliditydefend:latest ghcr.io/blocksecops/soliditydefend:latest
docker tag soliditydefend:latest ghcr.io/blocksecops/soliditydefend:1.0.0

# Push
docker push ghcr.io/blocksecops/soliditydefend:latest
docker push ghcr.io/blocksecops/soliditydefend:1.0.0
```

### Docker Hub

```bash
# Login
docker login

# Tag
docker tag soliditydefend:latest blocksecops/soliditydefend:latest
docker tag soliditydefend:latest blocksecops/soliditydefend:1.0.0

# Push
docker push blocksecops/soliditydefend:latest
docker push blocksecops/soliditydefend:1.0.0
```

---

## Additional Resources

- [Dockerfile Reference](https://docs.docker.com/engine/reference/builder/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Multi-stage Builds](https://docs.docker.com/build/building/multi-stage/)
- [BuildKit](https://docs.docker.com/build/buildkit/)

---

## Support

For Docker-related issues:
- Check [GitHub Issues](https://github.com/BlockSecOps/SolidityDefend/issues)
- Review [Troubleshooting](#troubleshooting) section above
- Consult [Docker Documentation](https://docs.docker.com/)

For general SolidityDefend support, see [README.md](../README.md).
