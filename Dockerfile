# Multi-stage build for SolidityDefend
# Builder stage
FROM rust:1.75-slim-bullseye AS builder

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

# Copy all crate Cargo.toml files to preserve workspace structure
COPY crates/soliditydefend/Cargo.toml ./crates/soliditydefend/
COPY crates/parser/Cargo.toml ./crates/parser/
COPY crates/ast/Cargo.toml ./crates/ast/
COPY crates/db/Cargo.toml ./crates/db/
COPY crates/semantic/Cargo.toml ./crates/semantic/
COPY crates/ir/Cargo.toml ./crates/ir/
COPY crates/cfg/Cargo.toml ./crates/cfg/
COPY crates/dataflow/Cargo.toml ./crates/dataflow/
COPY crates/analysis/Cargo.toml ./crates/analysis/
COPY crates/detectors/Cargo.toml ./crates/detectors/
COPY crates/output/Cargo.toml ./crates/output/
COPY crates/fixes/Cargo.toml ./crates/fixes/
COPY crates/cli/Cargo.toml ./crates/cli/
COPY crates/lsp/Cargo.toml ./crates/lsp/
COPY crates/cache/Cargo.toml ./crates/cache/
COPY crates/metrics/Cargo.toml ./crates/metrics/
COPY crates/performance/Cargo.toml ./crates/performance/
COPY tests/Cargo.toml ./tests/

# Create dummy lib.rs files for each crate to enable dependency caching
RUN mkdir -p crates/soliditydefend/src && echo "fn main() {}" > crates/soliditydefend/src/main.rs && \
    mkdir -p crates/parser/src && echo "" > crates/parser/src/lib.rs && \
    mkdir -p crates/ast/src && echo "" > crates/ast/src/lib.rs && \
    mkdir -p crates/db/src && echo "" > crates/db/src/lib.rs && \
    mkdir -p crates/semantic/src && echo "" > crates/semantic/src/lib.rs && \
    mkdir -p crates/ir/src && echo "" > crates/ir/src/lib.rs && \
    mkdir -p crates/cfg/src && echo "" > crates/cfg/src/lib.rs && \
    mkdir -p crates/dataflow/src && echo "" > crates/dataflow/src/lib.rs && \
    mkdir -p crates/analysis/src && echo "" > crates/analysis/src/lib.rs && \
    mkdir -p crates/detectors/src && echo "" > crates/detectors/src/lib.rs && \
    mkdir -p crates/output/src && echo "" > crates/output/src/lib.rs && \
    mkdir -p crates/fixes/src && echo "" > crates/fixes/src/lib.rs && \
    mkdir -p crates/cli/src && echo "" > crates/cli/src/lib.rs && \
    mkdir -p crates/lsp/src && echo "" > crates/lsp/src/lib.rs && \
    mkdir -p crates/cache/src && echo "" > crates/cache/src/lib.rs && \
    mkdir -p crates/metrics/src && echo "" > crates/metrics/src/lib.rs && \
    mkdir -p crates/performance/src && echo "" > crates/performance/src/lib.rs && \
    mkdir -p tests/src && echo "" > tests/src/lib.rs

# Build dependencies only (this layer will be cached)
RUN cargo build --release --bin soliditydefend || true

# Copy actual source code
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
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.description="High-performance static analysis security tool for Solidity smart contracts with 178 detectors" \
      org.opencontainers.image.authors="Advanced Blockchain Security" \
      org.opencontainers.image.vendor="BlockSecOps" \
      org.opencontainers.image.url="https://github.com/BlockSecOps/SolidityDefend" \
      org.opencontainers.image.source="https://github.com/BlockSecOps/SolidityDefend" \
      org.opencontainers.image.documentation="https://github.com/BlockSecOps/SolidityDefend/blob/main/README.md" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"