# Multi-stage build for SolidityDefend
# Builder stage
FROM rust:1.82-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy workspace configuration first
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY . .

# Build the application in release mode with optimizations
RUN cargo build --release --bin soliditydefend && \
    strip target/release/soliditydefend

# Runtime stage - minimal image for production
FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -r -s /bin/false soliditydefend

# Copy the binary from builder
COPY --from=builder /app/target/release/soliditydefend /usr/local/bin/soliditydefend

# Create working directory and set permissions
WORKDIR /workspace
RUN chown soliditydefend:soliditydefend /workspace

# Switch to non-root user for security
USER soliditydefend

# Set default entrypoint
ENTRYPOINT ["soliditydefend"]

# Default command shows help
CMD ["--help"]

# OCI Image Format Specification labels
LABEL org.opencontainers.image.title="SolidityDefend" \
      org.opencontainers.image.version="1.3.7" \
      org.opencontainers.image.description="High-performance static analysis security tool for Solidity smart contracts with 178 detectors" \
      org.opencontainers.image.authors="Advanced Blockchain Security" \
      org.opencontainers.image.vendor="BlockSecOps" \
      org.opencontainers.image.url="https://github.com/BlockSecOps/SolidityDefend" \
      org.opencontainers.image.source="https://github.com/BlockSecOps/SolidityDefend" \
      org.opencontainers.image.documentation="https://github.com/BlockSecOps/SolidityDefend/blob/main/README.md" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"