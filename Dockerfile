# Multi-stage build for SolidityDefend
FROM rust:1.75-slim-bullseye AS builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy dependency files first for better caching
COPY Cargo.toml Cargo.lock ./
COPY crates/*/Cargo.toml ./crates/*/

# Create dummy source files to cache dependencies
RUN find crates -name "Cargo.toml" -execdir sh -c 'mkdir -p src && echo "fn main() {}" > src/main.rs' \;
RUN cargo fetch

# Copy source code
COPY . .

# Build the application in release mode
RUN cargo build --release --bin soliditydefend

# Runtime stage
FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false soliditydefend

# Copy the binary
COPY --from=builder /app/target/release/soliditydefend /usr/local/bin/soliditydefend

# Create working directory
WORKDIR /workspace

# Switch to non-root user
USER soliditydefend

# Set default entrypoint
ENTRYPOINT ["soliditydefend"]

# Default command shows help
CMD ["--help"]

# Metadata
LABEL org.opencontainers.image.title="SolidityDefend"
LABEL org.opencontainers.image.description="Static security analysis tool for Solidity smart contracts"
LABEL org.opencontainers.image.vendor="SolidityDefend Project"
LABEL org.opencontainers.image.source="https://github.com/soliditydefend/soliditydefend"
LABEL org.opencontainers.image.documentation="https://docs.soliditydefend.com"