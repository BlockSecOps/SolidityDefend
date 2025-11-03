# Multi-stage build for SolidityDefend
FROM rust:1.75-slim as builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build dependencies (this is the cached layer)
RUN cargo build --release --bin soliditydefend

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false soliditydefend

# Copy the binary
COPY --from=builder /app/target/release/soliditydefend /usr/local/bin/soliditydefend

# Set proper permissions
RUN chmod +x /usr/local/bin/soliditydefend

# Create directories for analysis
RUN mkdir -p /analysis /output && \
    chown soliditydefend:soliditydefend /analysis /output

# Switch to non-root user
USER soliditydefend

# Set working directory
WORKDIR /analysis

# Default command
ENTRYPOINT ["soliditydefend"]
CMD ["--help"]

# Labels
LABEL maintainer="SolidityDefend Team"
LABEL description="Static analysis security testing tool for Solidity smart contracts"
LABEL version="1.3.0"